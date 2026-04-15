import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Extension implements BurpExtension {
    private JsonRpcCollector collector;
    private SecurityAnalyzerService securityAnalyzer;
    private WorkflowGraphService workflowGraphService;
    private EntityStoreService entityStoreService;
    private AttackSuggestionService attackSuggestionService;
    private AuthContextStore authContextStore;
    private LogicHunterExportService exportService;
    private Registration httpHandlerRegistration;
    private Registration dashboardTabRegistration;
    private Registration attackPlannerTabRegistration;
    private Registration unloadRegistration;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("LogicHunter");

        ObjectMapper objectMapper = new ObjectMapper();
        StorageManager storageManager = new StorageManager(
                montoyaApi.extension().filename(),
                objectMapper,
                montoyaApi.logging()
        );
        JsonRpcIndex index = new JsonRpcIndex();
        authContextStore = new AuthContextStore(objectMapper);
        collector = new JsonRpcCollector(montoyaApi, storageManager, index, authContextStore, objectMapper);
        registerHttpHandler(montoyaApi);

        securityAnalyzer = new SecurityAnalyzerService(objectMapper, index, authContextStore, montoyaApi.logging());
        workflowGraphService = new WorkflowGraphService(objectMapper, montoyaApi.logging(), authContextStore);
        entityStoreService = new EntityStoreService(objectMapper, montoyaApi.logging(), authContextStore);
        attackSuggestionService = new AttackSuggestionService(
            objectMapper,
            index,
            securityAnalyzer,
            workflowGraphService,
            entityStoreService,
            authContextStore,
            montoyaApi.logging()
        );
            exportService = new LogicHunterExportService(
                objectMapper,
                authContextStore,
                index,
                securityAnalyzer,
                entityStoreService,
                attackSuggestionService,
                workflowGraphService
            );

        // Consolidated 2-tab UI: Dashboard + Attack Planner
        DashboardTab dashboardTab = new DashboardTab(
                montoyaApi, collector, index, authContextStore,
                entityStoreService, exportService, objectMapper
        );
        AttackPlannerTab attackPlannerTab = new AttackPlannerTab(
                montoyaApi, attackSuggestionService, securityAnalyzer,
                workflowGraphService, authContextStore, collector, index, objectMapper
        );
        montoyaApi.userInterface().applyThemeToComponent(dashboardTab);
        montoyaApi.userInterface().applyThemeToComponent(attackPlannerTab);

        collector.registerIndexUpdateListener(dashboardTab::requestRefreshAsync);
        collector.registerIndexUpdateListener(attackSuggestionService::requestRecomputeAsync);
        collector.registerRecordListener((rawRecord, normalizedRecord, replayed) ->
            authContextStore.observeRecord(rawRecord, normalizedRecord.methodName())
        );
        collector.registerRecordListener(securityAnalyzer::ingestRecordAsync);
        collector.registerRecordListener(workflowGraphService::ingestRecordAsync);
        collector.registerRecordListener(entityStoreService::ingestRecordAsync);
        collector.registerRecordListener(attackSuggestionService::ingestRecordAsync);
        collector.registerResetListener(authContextStore::clear);
        collector.registerResetListener(securityAnalyzer::clear);
        collector.registerResetListener(workflowGraphService::clear);
        collector.registerResetListener(entityStoreService::clear);
        collector.registerResetListener(attackSuggestionService::clear);

        authContextStore.registerUpdateListener(dashboardTab::requestRefreshAsync);
        authContextStore.registerUpdateListener(attackSuggestionService::requestRecomputeAsync);
        authContextStore.registerUpdateListener(attackPlannerTab::requestRefreshAsync);

        securityAnalyzer.registerUpdateListener(attackPlannerTab::requestRefreshAsync);
        workflowGraphService.registerUpdateListener(attackPlannerTab::requestRefreshAsync);
        entityStoreService.registerUpdateListener(dashboardTab::requestRefreshAsync);
        attackSuggestionService.registerUpdateListener(attackPlannerTab::requestRefreshAsync);

        dashboardTabRegistration = montoyaApi.userInterface().registerSuiteTab("LogicHunter - Dashboard", dashboardTab);
        attackPlannerTabRegistration = montoyaApi.userInterface().registerSuiteTab("LogicHunter - Attack Planner", attackPlannerTab);
        unloadRegistration = montoyaApi.extension().registerUnloadingHandler(this::shutdown);

        collector.warmIndexFromDiskAsync();

        attackSuggestionService.requestRecomputeAsync();

        montoyaApi.logging().logToOutput("LogicHunter started. Data directory: " + storageManager.dataDirectory());
    }

    private void registerHttpHandler(MontoyaApi montoyaApi) {
        if (collector == null) {
            montoyaApi.logging().logToError("[LogicHunter] HTTP handler registration skipped: collector is null");
            return;
        }

        try {
            if (httpHandlerRegistration != null && httpHandlerRegistration.isRegistered()) {
                httpHandlerRegistration.deregister();
            }

            httpHandlerRegistration = montoyaApi.http().registerHttpHandler(collector);
            if (httpHandlerRegistration != null && httpHandlerRegistration.isRegistered()) {
                montoyaApi.logging().logToOutput("[LogicHunter] HTTP handler registered");
            } else {
                montoyaApi.logging().logToError("[LogicHunter] HTTP handler registration failed: registration not active");
            }
        } catch (Exception ex) {
            montoyaApi.logging().logToError("[LogicHunter] HTTP handler registration failed", ex);
        }
    }

    private void shutdown() {
        safeDeregister(httpHandlerRegistration);
        safeDeregister(dashboardTabRegistration);
        safeDeregister(attackPlannerTabRegistration);
        safeDeregister(unloadRegistration);

        if (collector != null) {
            collector.close();
        }
        if (securityAnalyzer != null) {
            securityAnalyzer.close();
        }
        if (workflowGraphService != null) {
            workflowGraphService.close();
        }
        if (entityStoreService != null) {
            entityStoreService.close();
        }
        if (attackSuggestionService != null) {
            attackSuggestionService.close();
        }
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