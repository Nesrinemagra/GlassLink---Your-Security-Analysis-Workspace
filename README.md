# GlassLink

> Security analysis desktop application for suspicious URLs and messages.

---

## ◆ 01. Project Name

**GlassLink**

---

## ◆ 02. Idea and Objectives

GlassLink is a Java desktop application that helps a user check suspicious content before trusting it.

Main objectives:

- • Detect dangerous URLs using VirusTotal reputation data.
- • Score suspicious messages locally using rule-based indicators.
- • Give an independent AI opinion for a URL or a message.
- • Support batch scanning from a CSV file.
- • Keep all API keys in backend configuration, never in the UI or source code.

The application has four main screens:

- • **Dashboard**: overview of the tool.
- • **Single Scan**: analyze one URL or one message.
- • **Batch Scan**: analyze many rows from a CSV file.
- • **AI Analysis**: ask the AI model to classify a URL or message.

---

## ◆ 03. How to Launch the Application

1. Install **JDK 21** and **Maven**.

2. Copy the example configuration file:

   ```powershell
   copy "GlassLink\app\config.properties.example" "GlassLink\app\config.properties"
   ```

3. Open `GlassLink/app/config.properties` and set your keys:

   ```properties
   virustotal.api.key=YOUR_VIRUSTOTAL_KEY
   ai.openai.api.key=YOUR_GROQ_KEY
   ```

   The Groq key is free. Create it at:

   ```text
   https://console.groq.com/keys
   ```

4. Launch the app from the `app` folder:

   ```powershell
   cd "GlassLink\app"
   mvn clean javafx:run
   ```

5. Run the tests:

   ```powershell
   cd "GlassLink\app"
   mvn test
   ```

Note: `config.properties` is read from the working directory, so launch Maven from `GlassLink/app`.

---

## ◆ 04. Tools and Languages

**Programming languages and UI files**

- • Java 21
- • FXML for the JavaFX screens
- • CSS for styling
- • `.properties` files for configuration
- • JSON for API responses

**Frameworks and libraries**

- • JavaFX 21.0.2
- • Maven
- • Gson 2.10.1
- • JUnit 5.10.2

**External services**

- • VirusTotal API for URL reputation.
- • Groq free OpenAI-compatible API for AI Analysis.
- • OpenCode local service is still supported as the original AI provider.

---

## ◆ 05. Additional Technical Information

### ▸ Project structure

After the folder rename:

- • `com.backend` contains the backend logic:
  - • `config`
  - • `model`
  - • `service`
  - • `ai`
- • `com.frontend` contains the JavaFX side:
  - • `Launcher`
  - • `Main`
  - • `controller`
  - • FXML views, CSS files, and images

The Maven group and artifact names were left unchanged to avoid unrelated build changes.

### ▸ Detection logic

**URL analysis**

- • Uses VirusTotal.
- • `Danger` when malicious or suspicious detections exist.
- • `Safe` only when a clean report already exists.
- • `Not Verified` for 404, missing key, network errors, or unknown responses.

**Message analysis**

- • Uses local rule-based scoring.
- • `Suspect` for medium/high scores.
- • `Low Risk` for low scores.
- • A message is never called `Safe`.

**Batch scan**

- • Reads CSV rows in `type,content` format.
- • Evaluates each row in the background.

### ▸ AI Analysis

The AI tab is independent from Single Scan and Batch Scan. It never changes VirusTotal or RuleAnalyzer results.

It sends a prompt to a text generator and parses a strict JSON answer with:

- • `type`
- • `status`
- • `risk`
- • `insights`

The AI page automatically detects whether the input is a URL or a message. The old type selector was removed.

### ▸ AI providers

Configuration key:

```properties
ai.provider=openai-compatible
```

Available values:

- • `openai-compatible`: uses Groq directly. This is the active free setup.
- • `opencode`: uses the original local OpenCode service.
- • `auto`: tries OpenCode first, then falls back to Groq.

Groq settings:

```properties
ai.openai.base.url=https://api.groq.com/openai/v1
ai.openai.model=openai/gpt-oss-20b
ai.openai.api.key=PASTE_GROQ_API_KEY_HERE
```

OpenCode settings remain available:

```properties
ai.opencode.url=http://127.0.0.1:PORT
ai.opencode.service-file=C:/Users/<you>/.local/state/opencode/service.json
ai.opencode.model=opencode/MODEL_ID
```

### ▸ Key safety

- • Never put API keys in Java files, FXML, CSS, or chat messages.
- • `config.properties` is not tracked by Git.
- • If a key was shared or pasted somewhere public, rotate it.

### ▸ Verification

The project has **68 JUnit tests**. They cover AI workflows, provider selection, configuration, CSV parsing, message rules, and threat evaluation.

Last verification:

```text
Tests run: 68, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```
