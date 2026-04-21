# LogicHunter (Burp Suite Extension)

LogicHunter is a passive Burp Suite extension (Montoya API) designed for analyzing JSON-RPC APIs and identifying **business logic flaws, access control issues, and workflow abuse**.

---

## ⚠️ Project Status

> 🚧 This project is **actively under development**.

* Core pipeline (capture, parsing, session tracking) is stable
* Analysis and suggestion engine are still evolving
* Some behaviors (session handling, correlation logic) are being refined

Use this tool as a **research assistant**, not a fully automated scanner.

---

## 🎯 Purpose

Testing JSON-RPC APIs manually is repetitive:

1. Login as ADMIN → capture traffic
2. Login as LOW PRIV → capture traffic
3. Compare behavior manually

LogicHunter automates the **analysis layer**, not exploitation.

---

## ⚙️ Features

* Passive JSON-RPC traffic capture
* Session tracking using:

  * host
  * database
  * sessionId
  * userName
* Role marking (ADMIN / LOW_PRIV)
* Entity extraction (IDs, groups, objects)
* Attack suggestion generation (in progress)
* Repeater-ready payload generation

---

## 🔐 Testing Workflow

Typical usage:

1. Login as LOW_PRIV user

2. Browse application → capture traffic

3. Mark session as LOW_PRIV

4. Logout

5. Login as ADMIN

6. Browse application → capture traffic

7. Mark session as ADMIN

8. Analyze differences in Attack Planner

---

## 🧠 What It Helps Find

* IDOR / BOLA
* Privilege escalation
* Broken access control
* Cross-tenant access
* Multicall abuse
* Workflow chaining vulnerabilities

---

## 🚫 What It Does NOT Do

* No active scanning
* No fuzzing
* No brute force
* No automatic exploitation

You stay in control (Burp Repeater workflow).

---

## 🧩 How It Works

```id="a6w2op"
traffic → parsing → context → entity tracking → analysis → suggestions
```

* Requests are captured passively
* Sessions are separated by context
* Entities are extracted and tracked
* Differences between roles are analyzed
* Suggestions are generated based on observed behavior

---

## 📦 Build

Requirements:

* JDK 21+

```bash
./gradlew build
./gradlew jar
```

Output:

```
build/libs/logic-hunter.jar
```

---

## 🔌 Load in Burp

1. Extensions → Installed
2. Add → Select JAR
3. Confirm:

   * LogicHunter - Dashboard
   * LogicHunter - Attack Planner

---

## 🧾 Data Storage

Logs stored in:

```
%USERPROFILE%\jsonrpc-logs\
```

Contains:

* raw traffic
* normalized data
* error logs

---

## 📌 Current Limitations

* Suggestion engine is still improving
* Context correlation may miss complex chains
* Some edge cases in session handling

---

## 🚀 Future Work

* Stronger exploit-chain detection
* Better cross-context comparison
* Improved session persistence
* More accurate prioritization of findings

---

## ⚠️ Disclaimer

This tool is for **authorized security testing only**.
Use responsibly and follow program rules.

---

## 🤝 Contribution

This project is evolving — feedback, ideas, and improvements are welcome.
