import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.methodminer.burp.BurpTrafficBridge;
import com.methodminer.burp.TrafficIngestor;
import com.methodminer.core.ProjectLifecycleManager;
import com.methodminer.core.events.SimpleEventBus;
import com.methodminer.core.repository.InMemorySurfaceRepository;
import com.methodminer.protocol.CompositeProtocolDetector;
import com.methodminer.protocol.ProtocolDetector;
import com.methodminer.protocol.graphql.GraphQlProtocolAnalyzer;
import com.methodminer.protocol.graphql.GraphQlProtocolDetector;
import com.methodminer.protocol.jsonrpc.JsonRpcProtocolAnalyzer;
import com.methodminer.protocol.jsonrpc.JsonRpcProtocolDetector;
import com.methodminer.session.InMemorySessionRepository;
import com.methodminer.session.SessionExtractor;
import com.methodminer.ui.MethodMinerTab;

import java.util.List;

public class Extension implements BurpExtension {
    private Registration v2BridgeRegistration;
    private Registration methodMinerTabRegistration;
    private Registration unloadRegistration;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("Method Miner");

        ObjectMapper objectMapper = new ObjectMapper();

        // v2 passive ingestion pipeline: JSON-RPC + GraphQL -> unified ApiSurface model
        SimpleEventBus v2EventBus = new SimpleEventBus();
        InMemorySurfaceRepository v2SurfaceRepository = new InMemorySurfaceRepository("Method Miner");
        ProtocolDetector v2ProtocolDetector = new CompositeProtocolDetector(List.of(
            new JsonRpcProtocolDetector(objectMapper),
            new GraphQlProtocolDetector(objectMapper)
        ));
        JsonRpcProtocolAnalyzer v2JsonRpcAnalyzer = new JsonRpcProtocolAnalyzer(objectMapper);
        GraphQlProtocolAnalyzer v2GraphQlAnalyzer = new GraphQlProtocolAnalyzer(objectMapper);
        SessionExtractor v2SessionExtractor = new SessionExtractor(objectMapper);
        InMemorySessionRepository v2SessionRepository = new InMemorySessionRepository();

        // Guarantee clean in-memory state on every extension load,
        // even if Burp hot-reloads without a full JVM restart.
        v2SurfaceRepository.clear();
        v2SessionRepository.clear();
        TrafficIngestor v2TrafficIngestor = new TrafficIngestor(
            v2ProtocolDetector,
            v2JsonRpcAnalyzer,
            v2GraphQlAnalyzer,
            v2SurfaceRepository,
            v2EventBus,
            v2SessionExtractor,
            v2SessionRepository
        );

        // Register the v2 bridge handler — feeds ALL Burp traffic into the v2 pipeline
        // (protocol detection and filtering are performed by the v2 pipeline itself).
        BurpTrafficBridge v2Bridge = new BurpTrafficBridge(v2TrafficIngestor, montoyaApi.logging());
        v2BridgeRegistration = montoyaApi.http().registerHttpHandler(v2Bridge);

        ProjectLifecycleManager lifecycleManager = new ProjectLifecycleManager(
                v2SurfaceRepository,
                v2SessionRepository,
                v2EventBus
        );

        MethodMinerTab methodMinerTab = new MethodMinerTab(
                v2EventBus,
                v2SurfaceRepository,
                v2SessionRepository,
                lifecycleManager
        );
        montoyaApi.userInterface().applyThemeToComponent(methodMinerTab);

        // Register only the unified v2 Method Miner tab.
        methodMinerTabRegistration = montoyaApi.userInterface().registerSuiteTab(MethodMinerTab.TAB_TITLE, methodMinerTab);
        unloadRegistration = montoyaApi.extension().registerUnloadingHandler(this::shutdown);

        montoyaApi.logging().logToOutput("Method Miner started (v2-only).");
    }

    private void shutdown() {
        safeDeregister(v2BridgeRegistration);
        safeDeregister(methodMinerTabRegistration);
        safeDeregister(unloadRegistration);
    }

    private static void safeDeregister(Registration registration) {
        if (registration == null) {
            return;
        }
        try {
            if (registration.isRegistered()) {
                registration.deregister();
            }
        } catch (Exception ignored) {
            // Avoid throwing during extension unload cleanup.
        }
    }
}