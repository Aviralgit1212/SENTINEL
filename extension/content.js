(() => {
  console.log("[AI Guardian] Content script loaded.");

  const SITE_CONFIG = {
    "chatgpt.com": {
      inputSelectors: [
        'textarea',
        'div[contenteditable="true"]'
      ],
      sendButtonSelectors: [
        'button[data-testid="send-button"]',
        'button[aria-label*="Send" i]',
        'button[type="submit"]'
      ]
    },

    "chat.openai.com": {
      inputSelectors: [
        'textarea',
        'div[contenteditable="true"]'
      ],
      sendButtonSelectors: [
        'button[data-testid="send-button"]',
        'button[aria-label*="Send" i]',
        'button[type="submit"]'
      ]
    },

    "claude.ai": {
      inputSelectors: [
        'textarea',
        'div[contenteditable="true"]'
      ],
      sendButtonSelectors: [
        'button[aria-label*="Send" i]',
        'button[data-testid="send-button"]',
        'button[type="submit"]'
      ]
    },

    "gemini.google.com": {
      inputSelectors: [
        'textarea',
        'div[contenteditable="true"]',
        '[role="textbox"]'
      ],
      sendButtonSelectors: [
        'button[aria-label*="Send" i]',
        'button[data-test-id*="send" i]',
        'button[type="submit"]'
      ]
    }
  };

  const hostname = window.location.hostname;
  const config = SITE_CONFIG[hostname];

  if (!config) {
    showUnsupportedSiteBanner();
    return;
  }

  console.log("[AI Guardian] Active on:", hostname);

  function showUnsupportedSiteBanner() {
    const key = "sentinelUnsupportedNoticeShown";
    try {
      if (sessionStorage.getItem(key) === "1") return;
      sessionStorage.setItem(key, "1");
    } catch (_) {
      // If page storage is unavailable, still show this one notice.
    }
    const banner = document.createElement("aside");
    banner.setAttribute("role", "status");
    banner.style.cssText = "position:fixed;top:12px;left:50%;transform:translateX(-50%);z-index:2147483647;max-width:min(620px,calc(100vw - 24px));padding:12px 16px;border-radius:10px;background:#78350f;color:#fff;font:14px/1.45 Arial,sans-serif;box-shadow:0 4px 20px rgba(0,0,0,.28);display:flex;gap:14px;align-items:center";
    const text = document.createElement("span");
    text.textContent = "Sentinel: This website is unsupported. Sentinel protection may not be active here.";
    const close = document.createElement("button");
    close.type = "button";
    close.textContent = "Dismiss";
    close.setAttribute("aria-label", "Dismiss Sentinel unsupported-site notice");
    close.style.cssText = "border:0;border-radius:5px;padding:6px 9px;background:#fff;color:#422006;cursor:pointer;white-space:nowrap";
    close.addEventListener("click", () => banner.remove());
    banner.append(text, close);
    (document.body || document.documentElement).appendChild(banner);
  }

  let allowNextSend = false;

  // Delayed reviewer-approval state for text submissions.
  let heldText = null;
  let heldTextInput = null;
  let heldTextMarker = null;
  let heldTextEventId = null;
  let approvedTextEventId = null;

  // Event IDs for held file/drop requests awaiting reviewer approval.
  let heldFileEventId = null;
  let heldDropEventId = null;

  // STEP 5G.1:
  // Hold the selected File object while the security decision is still pending.
  let heldFile = null;

  // STEP 5G.2:
  // Only one file scan is allowed at a time in this slice.
  let fileScanInProgress = false;

  // STEP 5G.3:
  // Allows one synthetic change event to pass through after ALLOW.
  let allowNextFileChange = false;

  // STEP 5G.4:
  // Allows one synthetic drop event to pass through after ALLOW.
  let allowNextDrop = false;

  // STEP 5G.4:
  // Track the drop operation for safe ALLOW redispatch.
  let heldDropTarget = null;
  let heldDropContainer = null;
  let heldDropMarker = null;

  // STEP 5G.3:
  // Track the exact logical file input used for the original selection.
  let heldFileInput = null;
  let heldFileInputMarker = null;
  let heldFileContainer = null;
  let heldFileAccept = null;
  let heldFileMultiple = false;
  let fileSelectionCounter = 0;

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "RELEASE_APPROVED") {
      handleApprovedRelease(message);
      return;
    }

    if (message.type === "RELEASE_TERMINAL") {
      handleTerminalRelease(message);
    }
  });

  function clearTextPendingState() {
    if (
      heldTextInput &&
      heldTextInput.isConnected &&
      heldTextMarker
    ) {
      if (
        heldTextInput.getAttribute(
          "data-ai-guardian-pending-text"
        ) === heldTextMarker
      ) {
        heldTextInput.removeAttribute(
          "data-ai-guardian-pending-text"
        );
      }
    }

    heldText = null;
    heldTextInput = null;
    heldTextMarker = null;
  }

  function clearHeldFileState() {
    heldFile = null;
    heldFileInput = null;
    heldFileContainer = null;
    heldFileInputMarker = null;
    heldFileAccept = null;
    heldFileMultiple = false;
    heldFileEventId = null;
    fileScanInProgress = false;
  }

  function clearHeldDropState() {
    if (
      heldDropTarget &&
      heldDropTarget.isConnected &&
      heldDropMarker
    ) {
      if (
        heldDropTarget.getAttribute(
          "data-ai-guardian-drop-pending"
        ) === heldDropMarker
      ) {
        heldDropTarget.removeAttribute(
          "data-ai-guardian-drop-pending"
        );
      }
    }

    heldFile = null;
    heldDropTarget = null;
    heldDropContainer = null;
    heldDropMarker = null;
    heldDropEventId = null;
    fileScanInProgress = false;
  }

  function showApprovalCompleteBanner(payloadType) {
    showBanner({
      decision: "APPROVED",
      risk: "REVIEWER-APPROVED",
      entities: [],
      approvalMessage:
        payloadType === "text"
          ? "Reviewer approved this exact message. You can send it now."
          : "Reviewer approved this exact file. It has been released back to the page."
    });
  }

  function handleApprovedRelease(message) {
    const eventId = message.eventId;

    if (message.payloadType === "text") {
      if (
        eventId !== heldTextEventId ||
        !heldTextInput ||
        !heldTextMarker
      ) {
        console.warn(
          "[AI Guardian] Approved text event does not match the held request."
        );
        return;
      }

      const markerMatches =
        heldTextInput.isConnected &&
        heldTextInput.getAttribute(
          "data-ai-guardian-pending-text"
        ) === heldTextMarker;

      const textMatches =
        getInputText(heldTextInput).trim() === heldText;

      if (!markerMatches || !textMatches) {
        console.warn(
          "[AI Guardian] Held text target changed. Release will not bypass a new scan."
        );

        heldTextEventId = null;
        approvedTextEventId = null;

        clearTextPendingState();

        showBanner({
          decision: "BLOCK",
          risk: "UNKNOWN",
          entities: [],
          error:
            "The original message changed or the original input disappeared. Please resubmit it."
        });

        return;
      }

      approvedTextEventId = eventId;

      heldTextInput.removeAttribute(
        "data-ai-guardian-pending-text"
      );

      showApprovalCompleteBanner("text");

      return;
    }

    if (
      message.payloadType === "file" &&
      eventId === heldFileEventId
    ) {
      const released = releaseHeldFile();

      if (released) {
        clearHeldFileState();
        showApprovalCompleteBanner("file");
      } else {
        clearHeldFileState();
      }

      return;
    }

    if (
      message.payloadType === "file" &&
      eventId === heldDropEventId
    ) {
      const released = releaseHeldDropFile();

      if (released) {
        clearHeldDropState();
        showApprovalCompleteBanner("file");
      } else {
        clearHeldDropState();
      }
    }
  }

  function handleTerminalRelease(message) {
    const state = message.state;
    const eventId = message.eventId;

    if (
      message.payloadType === "text" &&
      (
        eventId === heldTextEventId ||
        eventId === approvedTextEventId
      )
    ) {
      heldTextEventId = null;
      approvedTextEventId = null;
      clearTextPendingState();
    }

    if (
      message.payloadType === "file" &&
      eventId === heldFileEventId
    ) {
      clearHeldFileState();
    }

    if (
      message.payloadType === "file" &&
      eventId === heldDropEventId
    ) {
      clearHeldDropState();
    }

    showBanner({
      decision: "BLOCK",
      risk: "UNKNOWN",
      entities: [],
      error:
        `Reviewer approval ${state.toLowerCase()}. The request remains blocked.`
    });
  }

  function isVisible(element) {
    if (!element) return false;

    const rect = element.getBoundingClientRect();

    return (
      rect.width > 0 &&
      rect.height > 0 &&
      getComputedStyle(element).visibility !== "hidden" &&
      getComputedStyle(element).display !== "none"
    );
  }

  function findElement(selectors) {
    for (const selector of selectors) {
      const elements = document.querySelectorAll(selector);

      for (const element of elements) {
        if (isVisible(element)) {
          return element;
        }
      }
    }

    return null;
  }

  function getInputElement() {
    return findElement(config.inputSelectors);
  }

  function getInputText(input) {
    if (!input) return "";

    if (input.tagName === "TEXTAREA") {
      return input.value;
    }

    return input.innerText || input.textContent || "";
  }

  function findSendButton() {
    return findElement(config.sendButtonSelectors);
  }

  function isSendButton(element) {
    if (!element) return false;

    return config.sendButtonSelectors.some((selector) => {
      try {
        return element.matches(selector);
      } catch {
        return false;
      }
    });
  }

  function clearInputText(inputElement) {
    if (!inputElement) return;

    if (inputElement.tagName === "TEXTAREA") {
      /*
       * React and similar frameworks may track a textarea's value
       * through their own property handling. Setting .value = ""
       * directly does not always notify those frameworks.
       *
       * The native prototype setter performs the real DOM update,
       * then the input event tells the framework that the value changed.
       */
      const setter = Object.getOwnPropertyDescriptor(
        HTMLTextAreaElement.prototype,
        "value"
      ).set;

      setter.call(inputElement, "");

      inputElement.dispatchEvent(
        new Event("input", {
          bubbles: true
        })
      );

      return;
    }

    if (inputElement.isContentEditable) {
      inputElement.textContent = "";

      inputElement.dispatchEvent(
        new InputEvent("input", {
          bubbles: true,
          inputType: "deleteContentBackward",
          data: null
        })
      );
    }
  }

  function showBanner(scanResult, options = {}) {
    const oldBanner = document.getElementById("ai-guardian-banner");

    if (oldBanner) {
      oldBanner.remove();
    }

    const decision = scanResult.decision;
    const isBlocked = decision === "BLOCK";
    const isIncomplete = decision === "INCOMPLETE";
    const isFailure = Boolean(scanResult.error) || scanResult.scan_status === "FAILED";
    const isRedacted = decision === "REDACT";
    const isApproved = decision === "APPROVED";

    const redactedText = options.redactedText;

    /*
     * Backend returns "entities".
     * The fallback to "findings" keeps this display function
     * compatible with older versions of the extension.
     */
    const entities =
      Array.isArray(scanResult.entities)
        ? scanResult.entities
        : Array.isArray(scanResult.findings)
          ? scanResult.findings
          : [];

    const entityTypes = entities.length
      ? [...new Set(
          entities.map((entity) =>
            entity.entity_type || entity.type || "UNKNOWN"
          )
        )].join(", ")
      : "None";

    let heading;
    let body;
    let background;

    if (isApproved) {
      heading = "🟢 Reviewer Approved";
      body =
        scanResult.approvalMessage ||
        "This exact request was approved by the reviewer.";
      background = "#166534";
    } else if (isFailure) {
      heading = "⚠️ Sentinel protection unavailable";
      body = "Sentinel could not complete this scan. The intercepted submission was held and was not released to the website. Retry after the local backend or extension is available.";
      background = "#7f1d1d";
    } else if (isIncomplete) {
      heading = "⚠️ Inspection incomplete — blocked";
      body = "Sentinel could not inspect all required content, so this intercepted submission was not released. Submit again after resolving the inspection limitation.";
      background = "#7f1d1d";
    } else if (isBlocked) {
      heading = "🔴 Message Blocked";
      body =
        scanResult.approvalMessage ||
        "This message contains sensitive data that violates policy and was not sent.";
      background = "#7f1d1d";
    } else if (isRedacted) {
      heading = "🟡 Sensitive Info Redacted";
      body =
        "A safe version of your message is ready. " +
        "Click Copy Safe Version to copy it, then paste it (Ctrl+V) into the chat box and send it yourself if you're happy with it.";
      background = "#92400e";
    } else {
      heading = "⚠️ Sensitive Data Detected";
      body = "The message requires attention before being sent.";
      background = "#92400e";
    }

    const banner = document.createElement("div");

    banner.id = "ai-guardian-banner";

    banner.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 2147483647;
      width: 360px;
      padding: 16px;
      border-radius: 12px;
      background: ${background};
      color: white;
      font-family: Arial, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      box-shadow: 0 8px 30px rgba(0,0,0,0.35);
    `;

    banner.innerHTML = `
      <strong style="font-size:16px;">
        ${heading}
      </strong>

      <div style="margin-top:8px;">
        Risk: <strong>${escapeHtml(scanResult.risk || "UNKNOWN")}</strong>
      </div>

      <div>
        Decision: <strong>${escapeHtml(decision || "UNKNOWN")}</strong>
      </div>

      <div>
        Detected: <strong>${escapeHtml(entityTypes)}</strong>
      </div>

      <div style="margin-top:10px;">
        ${escapeHtml(body)}
      </div>

      ${
        isRedacted
          ? `
            <button
              id="ai-guardian-copy-safe"
              style="
                margin-top:12px;
                padding:8px 12px;
                border:0;
                border-radius:6px;
                cursor:pointer;
                font-weight:600;
              "
            >
              Copy Safe Version
            </button>
          `
          : ""
      }

      <button
        id="ai-guardian-close"
        style="
          margin-top:12px;
          margin-left:8px;
          padding:6px 12px;
          border:0;
          border-radius:6px;
          cursor:pointer;
        "
      >
        Close
      </button>
    `;

    document.body.appendChild(banner);

    const closeButton =
      document.getElementById("ai-guardian-close");

    if (closeButton) {
      closeButton.addEventListener("click", () => {
        banner.remove();
      });
    }

    /*
     * Clipboard access happens only after the user explicitly
     * clicks "Copy Safe Version". This makes the copy action
     * a fresh user gesture instead of relying on the earlier
     * asynchronous backend request.
     */
    if (isRedacted) {
      const copyButton =
        document.getElementById("ai-guardian-copy-safe");

      if (copyButton && typeof redactedText === "string") {
        copyButton.addEventListener("click", async () => {
          console.log(
            "[AI Guardian] User clicked Copy Safe Version."
          );

          try {
            await navigator.clipboard.writeText(redactedText);

            console.log(
              "[AI Guardian] Redacted text copied to clipboard successfully."
            );

            copyButton.textContent = "Copied!";

            setTimeout(() => {
              if (copyButton.isConnected) {
                copyButton.textContent = "Copy Safe Version";
              }
            }, 2000);
          } catch (error) {
            console.error(
              "[AI Guardian] Could not copy redacted text to clipboard:",
              error
            );

            copyButton.textContent =
              "Copy failed — try manually";
          }
        });
      }
    }

    setTimeout(() => {
      if (banner.isConnected) {
        banner.remove();
      }
    }, 10000);
  }


  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (character) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[character]));
  }


  function showCacheChoice(offer, onChoice) {
    const previous = document.getElementById("sentinel-cache-choice");
    if (previous) previous.remove();
    const panel = document.createElement("section");
    panel.id = "sentinel-cache-choice";
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-label", "Sentinel cached report choice");
    panel.style.cssText = "position:fixed;top:20px;right:20px;z-index:2147483647;width:min(420px,calc(100vw - 40px));padding:18px;border-radius:12px;background:#1e293b;color:#fff;font:14px/1.5 Arial,sans-serif;box-shadow:0 8px 30px rgba(0,0,0,.4)";
    const heading = document.createElement("strong");
    heading.textContent = "Sentinel found a compatible previous report";
    const detail = document.createElement("p");
    detail.textContent = `Previous result: ${String(offer.decision || "UNKNOWN")} (${String(offer.risk || "UNKNOWN")}); originally analyzed: ${String(offer.analysis_timestamp || "unknown")}.`;
    const note = document.createElement("p");
    note.textContent = offer.reuse_allowed
      ? "Choose whether to reuse this report for this exact file or run the complete scan again."
      : "This result cannot safely be reused (including cached REDACT results); run a fresh scan to regenerate and verify output.";
    const actions = document.createElement("div");
    actions.style.cssText = "display:flex;gap:8px;flex-wrap:wrap;margin-top:12px";
    const button = (label, value) => {
      const element = document.createElement("button");
      element.type = "button";
      element.textContent = label;
      element.style.cssText = "border:0;border-radius:6px;padding:8px 10px;cursor:pointer;font-weight:600";
      element.addEventListener("click", () => finish(value));
      return element;
    };
    let settled = false;
    const timeout = setTimeout(() => finish(null), 20 * 60 * 1000);
    function finish(choice) {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      panel.remove();
      onChoice(choice);
    }
    if (offer.reuse_allowed) actions.appendChild(button("Reuse previous report", "reuse"));
    actions.appendChild(button("Run fresh scan", "rescan"));
    actions.appendChild(button("Keep unreleased", null));
    panel.append(heading, detail, note, actions);
    (document.body || document.documentElement).appendChild(panel);
  }


  function triggerRealSend(inputElement) {
    console.log("[AI Guardian] Re-triggering original send.");

    allowNextSend = true;

    const sendButton = findSendButton();

    if (sendButton) {
      console.log("[AI Guardian] Clicking real send button.");
      sendButton.click();
      return;
    }

    console.log("[AI Guardian] Send button not found. Trying Enter.");

    const event = new KeyboardEvent("keydown", {
      key: "Enter",
      code: "Enter",
      bubbles: true,
      cancelable: true
    });

    inputElement.dispatchEvent(event);
  }

  function handleSubmitAttempt(event) {
    if (approvedTextEventId) {
      const inputElement = getInputElement();

      const markerMatches =
        inputElement &&
        inputElement === heldTextInput &&
        heldTextMarker &&
        inputElement.getAttribute(
          "data-ai-guardian-pending-text"
        ) === heldTextMarker;

      const textMatches =
        inputElement &&
        getInputText(inputElement).trim() === heldText;

      if (markerMatches && textMatches) {
        approvedTextEventId = null;
        heldTextEventId = null;

        inputElement.removeAttribute(
          "data-ai-guardian-pending-text"
        );

        clearTextPendingState();

        allowNextSend = true;

        return;
      }

      approvedTextEventId = null;
      clearTextPendingState();
    }

    if (allowNextSend) {
      console.log(
        "[AI Guardian] Allowing programmatic send to pass through."
      );

      allowNextSend = false;
      return;
    }

    const inputElement = getInputElement();

    if (!inputElement) {
      console.log("[AI Guardian] Prompt input not found.");
      return;
    }

    const text = getInputText(inputElement).trim();

    if (!text) {
      console.log("[AI Guardian] Empty message. Ignoring.");
      return;
    }

    event.preventDefault();
    event.stopImmediatePropagation();

    console.log("[AI Guardian] Submit attempt detected.");
    console.log("[AI Guardian] Sending scan request to background...");

    chrome.runtime.sendMessage(
      {
        type: "SCAN_REQUEST",
        text: text,
        site: window.location.origin
      },
      (response) => {
        if (chrome.runtime.lastError) {
          console.error(
            "[AI Guardian] Extension message error:",
            chrome.runtime.lastError.message
          );

          showBanner({
            decision: "INCOMPLETE",
            scan_status: "FAILED",
            risk: "UNKNOWN",
            entities: [],
            error: "Sentinel could not reach the scan worker. The intercepted message was not released."
          });

          return;
        }

        if (!response) {
          console.error("[AI Guardian] Empty response from Guardian.");

          showBanner({
            decision: "INCOMPLETE",
            scan_status: "FAILED",
            risk: "UNKNOWN",
            entities: [],
            error: "No scan result was received. The intercepted message was not released."
          });

          return;
        }

        if (response.decision === "ALLOW") {
          console.log("[AI Guardian] Decision = ALLOW");
          console.log("[AI Guardian] Sending original message.");

          triggerRealSend(inputElement);
          return;
        }

        if (response.decision === "BLOCK") {
          console.log("[AI Guardian] Decision = BLOCK");
          console.log("[AI Guardian] Message will NOT be sent.");

          if (
            response.event_id &&
            response.release_token
          ) {
            heldText = text;
            heldTextInput = inputElement;

            heldTextMarker =
              `ai-guardian-text-${response.event_id}`;

            heldTextInput.setAttribute(
              "data-ai-guardian-pending-text",
              heldTextMarker
            );

            heldTextEventId =
              response.event_id;
          }

          showBanner({
            ...response,
            approvalMessage: response.event_id
              ? "Blocked — sent for reviewer approval. Keep this exact message unchanged until approval arrives."
              : undefined
          });

          return;
        }

        if (response.decision === "REDACT") {
          console.log("[AI Guardian] Decision = REDACT");

          const redactedText = response.redacted_text;

          if (typeof redactedText !== "string") {
            console.error(
              "[AI Guardian] REDACT response has no valid redacted_text."
            );

            showBanner({
              ...response,
              entities: response.entities || []
            });

            return;
          }

          clearInputText(inputElement);

          console.log("[AI Guardian] Original input cleared.");

          showBanner(response, {
            redactedText
          });

          return;
        }


        if (response.decision === "INCOMPLETE") {
          showBanner(response);
          return;
        }

        console.warn(
          "[AI Guardian] Unknown decision:",
          response.decision
        );

        showBanner({
          decision: "BLOCK",
          risk: "UNKNOWN",
          entities: []
        });
      }
    );
  }

  document.addEventListener(
    "keydown",
    (event) => {
      if (event.key !== "Enter") return;

      if (event.shiftKey) return;

      if (event.isComposing) return;

      const inputElement = getInputElement();

      if (!inputElement) return;

      const activeElement = document.activeElement;

      const inputIsFocused =
        activeElement === inputElement ||
        inputElement.contains(activeElement);

      if (!inputIsFocused) return;

      console.log("[AI Guardian] Enter detected.");

      handleSubmitAttempt(event);
    },
    true
  );

  document.addEventListener(
    "click",
    (event) => {
      if (!(event.target instanceof Element)) return;

      const clickedElement = event.target.closest("button");

      if (!clickedElement) return;

      if (!isSendButton(clickedElement)) return;

      console.log("[AI Guardian] Send button click detected.");

      handleSubmitAttempt(event);
    },
    true
  );


  // --------------------------------------------------
  // FILE DETECTION — metadata only
  // --------------------------------------------------

  function handleFileSelection(file, onScanResponse = null, cacheChoice = null) {
    if (!file) return;

    if (file.size > 25 * 1024 * 1024) {
      if (typeof onScanResponse === "function") {
        onScanResponse({
          decision: "INCOMPLETE",
          scan_status: "INCOMPLETE",
          risk: "UNKNOWN",
          entities: [],
          error: "File exceeds Sentinel's 25 MB limit. The intercepted submission was not released."
        });
      }
      return;
    }

    console.log("[AI Guardian] File detected.");
    // Step 5C: read the actual file bytes and convert them to Base64.
    const reader = new FileReader();

    reader.onload = () => {
      try {
        const dataUrl = reader.result;

        if (typeof dataUrl !== "string") {
          throw new Error("FileReader returned an unexpected result.");
        }

        // readAsDataURL() returns something like:
        // data:application/pdf;base64,JVBERi0xLjQK...
        // We only need the Base64 part after the comma.
        const commaIndex = dataUrl.indexOf(",");

        if (commaIndex === -1) {
          throw new Error("Could not extract Base64 data from file.");
        }

        const base64String = dataUrl.slice(commaIndex + 1);

        console.log(
          "[AI Guardian] File converted to Base64."
        );

        const message = {
          type: "FILE_UPLOAD",
          name: file.name,
          fileType: file.type,
          size: file.size,
          data: base64String,
          site: window.location.origin,
          cacheChoice
        };

        if (typeof onScanResponse === "function") {
          // 5G.2: request the backend decision and wait for its response.
          chrome.runtime.sendMessage(
            message,
            (response) => {
              if (chrome.runtime.lastError) {
                onScanResponse({
                  decision: "INCOMPLETE",
                  scan_status: "FAILED",
                  risk: "UNKNOWN",
                  entities: [],
                  error: chrome.runtime.lastError.message
                });

                return;
              }

              if (response?.decision === "CACHE_CHOICE_REQUIRED") {
                showCacheChoice(response.cache_offer || {}, (choice) => {
                  if (choice === "reuse" || choice === "rescan") {
                    handleFileSelection(file, onScanResponse, choice);
                  } else {
                    onScanResponse({
                      decision: "INCOMPLETE", scan_status: "INCOMPLETE",
                      risk: "UNKNOWN", entities: [],
                      error: "No cached report was selected. The intercepted file remains unreleased."
                    });
                  }
                });
                return;
              }

              onScanResponse(response);
            }
          );
        } else {
          // Existing pre-5G.2 file flow for paths not yet being enforced.
          chrome.runtime.sendMessage(message);
        }

        console.log(
          "[AI Guardian] File bytes sent to background as Base64."
        );
      } catch (error) {
        console.error(
          "[AI Guardian] Could not prepare file for byte transfer:",
          error
        );

        if (typeof onScanResponse === "function") {
          onScanResponse({
            decision: "INCOMPLETE",
            scan_status: "FAILED",
            risk: "UNKNOWN",
            entities: [],
            error: error.message
          });
        }
      }
    };

    reader.onerror = () => {
      console.error(
        "[AI Guardian] Could not read file:",
        reader.error
      );

    if (typeof onScanResponse === "function") {
      onScanResponse({
        decision: "INCOMPLETE",
        scan_status: "FAILED",
          risk: "UNKNOWN",
          entities: [],
          error: "Could not read file."
        });
      }
    };

    reader.readAsDataURL(file);
  }

  // --------------------------------------------------
  // STEP 5G.1 — FILE PICKER INTERCEPT / HOLD / CLEAR
  // No backend call yet.
  // --------------------------------------------------

  function showFileNotReleasedBanner(scanResult) {
    const oldBanner = document.getElementById("ai-guardian-banner");

    if (oldBanner) {
      oldBanner.remove();
    }

    const entities = Array.isArray(scanResult.entities)
      ? scanResult.entities
      : [];

    const entityTypes = entities.length
      ? [...new Set(
          entities.map((entity) =>
            escapeHtml(entity.entity_type || entity.type || "UNKNOWN")
          )
        )].join(", ")
      : "None";

    const incomplete = scanResult.decision === "INCOMPLETE" || scanResult.scan_status === "FAILED";
    const message = incomplete
      ? "Sentinel could not complete inspection. The intercepted file was not released; retry after the local backend or extension is available."
      : "Sentinel could not establish a safe decision. The intercepted file was not released.";

    const banner = document.createElement("div");

    banner.id = "ai-guardian-banner";
    banner.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 2147483647;
      width: 360px;
      padding: 16px;
      border-radius: 12px;
      background: #92400e;
      color: white;
      font-family: Arial, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      box-shadow: 0 8px 30px rgba(0,0,0,0.35);
    `;

    banner.innerHTML = `
      <strong style="font-size:16px;">
        ${incomplete ? "Inspection Incomplete" : "File Not Released"}
      </strong>

      <div style="margin-top:8px;">
        Risk: <strong>${escapeHtml(scanResult.risk || "UNKNOWN")}</strong>
      </div>

      <div>
        Decision: <strong>${escapeHtml(scanResult.decision || "UNKNOWN")}</strong>
      </div>

      <div>
        Detected: <strong>${entityTypes}</strong>
      </div>

      <div style="margin-top:10px;">
        ${message}
      </div>

      <button
        id="ai-guardian-close"
        style="
          margin-top:12px;
          padding:6px 12px;
          border:0;
          border-radius:6px;
          cursor:pointer;
        "
      >
        Close
      </button>
    `;

    document.body.appendChild(banner);

    const closeButton =
      document.getElementById("ai-guardian-close");

    if (closeButton) {
      closeButton.addEventListener("click", () => {
        banner.remove();
      });
    }

    setTimeout(() => {
      if (banner.isConnected) {
        banner.remove();
      }
    }, 10000);
  }


  // --------------------------------------------------
  // STEP 5H — FILE REDACT / SAFE VERSION DOWNLOAD
  // --------------------------------------------------

  function showFileRedactedBanner(scanResult) {
    const oldBanner =
      document.getElementById("ai-guardian-banner");

    if (oldBanner) {
      oldBanner.remove();
    }

    const entities = Array.isArray(scanResult.entities)
      ? scanResult.entities
      : [];

    const entityTypes = entities.length
      ? [...new Set(
          entities.map((entity) =>
            entity.entity_type || entity.type || "UNKNOWN"
          )
        )].join(", ")
      : "None";

    const redactedBase64 =
      scanResult.redacted_file_base64;

    const redactedMimeType =
      scanResult.redacted_mime_type;

    const redactedFilename =
      scanResult.redacted_filename;

    /*
     * A REDACT response without a generated safe file is not safe
     * to release. Fail closed rather than silently doing nothing.
     */
    if (
      typeof redactedBase64 !== "string" ||
      redactedBase64.trim().length === 0
    ) {
      console.error(
        "[AI Guardian] STEP 5H: REDACT decision received without a redacted file. Failing closed."
      );

      showBanner({
        decision: "BLOCK",
        risk: scanResult.risk || "UNKNOWN",
        entities,
        error:
          "Could not generate a safe version of this file — blocked."
      });

      return;
    }

    const banner =
      document.createElement("div");

    banner.id =
      "ai-guardian-banner";

    banner.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 2147483647;
      width: 390px;
      padding: 16px;
      border-radius: 12px;
      background: #92400e;
      color: white;
      font-family: Arial, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      box-shadow: 0 8px 30px rgba(0,0,0,0.35);
    `;

    const isImage =
      typeof redactedMimeType === "string" &&
      redactedMimeType.toLowerCase().startsWith("image/");

    banner.innerHTML = `
      <strong style="font-size:16px;">
        🟡 File Redacted
      </strong>

      <div style="margin-top:8px;">
        Risk: <strong>${scanResult.risk || "UNKNOWN"}</strong>
      </div>

      <div>
        Decision: <strong>REDACT</strong>
      </div>

      <div>
        Detected: <strong>${entityTypes}</strong>
      </div>

      <div style="margin-top:10px;">
        A safe version of the file was generated. The original file was not
        released to the AI.
      </div>

      ${
        isImage
          ? `
              <div style="margin-top:10px;">
                The sensitive content detected in this image was permanently
                covered and the safe image was re-scanned before release.
              </div>
            `
          : `
              <div style="margin-top:10px;">
                <strong>Important:</strong> Text-based sensitive content removed —
                this does not scan or redact content inside embedded images.
              </div>
            `
      }

      <button
        id="ai-guardian-download-redacted"
        style="
          margin-top:14px;
          padding:9px 14px;
          border:0;
          border-radius:7px;
          cursor:pointer;
          font-weight:600;
        "
      >
        Download Safe Version
      </button>

      <button
        id="ai-guardian-close"
        style="
          margin-top:14px;
          margin-left:8px;
          padding:7px 12px;
          border:0;
          border-radius:7px;
          cursor:pointer;
        "
      >
        Close
      </button>

      <div style="margin-top:10px; font-size:12px; opacity:0.9;">
        After downloading, manually re-attach the safe file. Guardian will
        scan it again before release.
      </div>
    `;

    document.body.appendChild(
      banner
    );

    const downloadButton =
      document.getElementById(
        "ai-guardian-download-redacted"
      );

    const closeButton =
      document.getElementById(
        "ai-guardian-close"
      );

    if (closeButton) {
      closeButton.addEventListener(
        "click",
        () => {
          banner.remove();
        }
      );
    }

    if (downloadButton) {
      downloadButton.addEventListener(
        "click",
        () => {
          try {
            console.log(
              "[AI Guardian] STEP 5H: User requested the redacted file download."
            );

            if (
              typeof redactedMimeType !== "string" ||
              redactedMimeType.trim().length === 0
            ) {
              throw new Error(
                "Redacted response has no valid MIME type."
              );
            }

            if (
              typeof redactedFilename !== "string" ||
              redactedFilename.trim().length === 0
            ) {
              throw new Error(
                "Redacted response has no valid filename."
              );
            }

            const binaryString =
              atob(
                redactedBase64
              );

            const bytes =
              new Uint8Array(
                binaryString.length
              );

            for (
              let index = 0;
              index < binaryString.length;
              index++
            ) {
              bytes[index] =
                binaryString.charCodeAt(
                  index
                );
            }

            const blob =
              new Blob(
                [bytes],
                {
                  type: redactedMimeType
                }
              );

            const objectUrl =
              URL.createObjectURL(
                blob
              );

            const anchor =
              document.createElement(
                "a"
              );

            anchor.href =
              objectUrl;

            anchor.download =
              redactedFilename;

            anchor.style.display =
              "none";

            document.body.appendChild(
              anchor
            );

            /*
             * The click happens directly inside the user's click handler,
             * so this remains an explicit user gesture.
             */
            anchor.click();

            setTimeout(
              () => {
                URL.revokeObjectURL(
                  objectUrl
                );

                anchor.remove();
              },
              1000
            );

            downloadButton.textContent =
              "Downloaded ✓";

            console.log(
              "[AI Guardian] STEP 5H: Redacted file download triggered:",
              anchor.download,
              redactedMimeType
            );
          } catch (error) {
            console.error(
              "[AI Guardian] STEP 5H: Failed to download redacted file:",
              error
            );

            /*
             * The file already passed backend redaction verification,
             * so download failure does not release the original file.
             */
            downloadButton.textContent =
              "Download failed";
          }
        }
      );
    }
  }


  // --------------------------------------------------
  // STEP 5G.3 — FILE ALLOW / REINJECTION
  // --------------------------------------------------

  function findFreshFileInput() {
    /*
     * Layer 1:
     * Reuse the exact original input if React kept it connected.
     */
    if (
      heldFileInput &&
      heldFileInput.isConnected
    ) {
      console.log(
        "[AI Guardian] STEP 5G.3: Layer 1 — original reference isConnected: true"
      );

      return heldFileInput;
    }

    console.log(
      "[AI Guardian] STEP 5G.3: Layer 1 — original reference isConnected: false"
    );

    /*
     * Layer 2:
     * If the original node was replaced, search only within the
     * previously captured container and match the unique marker.
     */
    if (
      heldFileContainer &&
      heldFileContainer.isConnected &&
      heldFileInputMarker
    ) {
      const candidates =
        heldFileContainer.querySelectorAll(
          'input[type="file"]'
        );

      console.log(
        "[AI Guardian] STEP 5G.3: Layer 2 — candidates found in container scope:",
        candidates.length
      );

      for (
        const candidate
        of candidates
      ) {
        if (
          candidate.getAttribute(
            "data-ai-guardian-pending"
          ) === heldFileInputMarker
        ) {
          console.log(
            "[AI Guardian] STEP 5G.3: Layer 2 — marker match found: true"
          );

          return candidate;
        }
      }

      console.log(
        "[AI Guardian] STEP 5G.3: Layer 2 — marker match found: false"
      );

      /*
       * Layer 3:
       * Match accept + multiple only if exactly one candidate remains.
       */
      const attributeMatches =
        Array.from(
          candidates
        ).filter(
          (candidate) => {
            const acceptMatches =
              (
                candidate.getAttribute(
                  "accept"
                ) || null
              ) === heldFileAccept;

            const multipleMatches =
              candidate.hasAttribute(
                "multiple"
              ) === heldFileMultiple;

            return (
              acceptMatches &&
              multipleMatches
            );
          }
        );

      console.log(
        "[AI Guardian] STEP 5G.3: Layer 3 — candidates after attribute filter:",
        attributeMatches.length
      );

      if (
        attributeMatches.length === 1
      ) {
        const fallbackInput =
          attributeMatches[0];

        fallbackInput.setAttribute(
          "data-ai-guardian-pending",
          heldFileInputMarker
        );

        console.log(
          "[AI Guardian] STEP 5G.3: Layer 3 — unique attribute match tagged with pending marker."
        );

        return fallbackInput;
      }
    } else {
      console.log(
        "[AI Guardian] STEP 5G.3: Layer 2 — stable container unavailable."
      );
    }

    console.error(
      "[AI Guardian] STEP 5G.3: No verified input found — aborting injection, showing manual re-attach banner."
    );

    return null;
  }

  // TEMP DEBUG — remove after 5G.3 diagnosis.
  function logCurrentFileInputsForDebug(
    selectedInput = null
  ) {
    const fileInputs =
      document.querySelectorAll(
        'input[type="file"]'
      );

    console.log(
      "[AI Guardian] TEMP DEBUG: Current file input count:",
      fileInputs.length
    );

    let markedPresent =
      false;

    let selectedIndex =
      -1;

    fileInputs.forEach(
      (
        input,
        index
      ) => {
        const accept =
          input.getAttribute(
            "accept"
          );

        const multiple =
          input.hasAttribute(
            "multiple"
          );

        const marked =
          input.dataset.aiGuardianOriginal ===
          "true";

        const selected =
          input === selectedInput;

        if (marked) {
          markedPresent =
            true;
        }

        if (selected) {
          selectedIndex =
            index;
        }

        console.log(
          `[AI Guardian] TEMP DEBUG: input[${index}] accept=${accept || "(none)"} multiple=${multiple} marked=${marked} selected=${selected}`
        );
      }
    );

    console.log(
      "[AI Guardian] TEMP DEBUG: selected/current lookup index:",
      selectedIndex
    );

    console.log(
      "[AI Guardian] TEMP DEBUG: marked original input exists anywhere now:",
      markedPresent
    );

    if (selectedInput) {
      console.log(
        "[AI Guardian] TEMP DEBUG: selected input accept:",
        selectedInput.getAttribute(
          "accept"
        ) || "(none)"
      );

      console.log(
        "[AI Guardian] TEMP DEBUG: selected input multiple:",
        selectedInput.hasAttribute(
          "multiple"
        )
      );

      console.log(
        "[AI Guardian] TEMP DEBUG: selected input carries original marker:",
        selectedInput.dataset.aiGuardianOriginal ===
          "true"
      );
    }

    return {
      fileInputs,
      markedPresent,
      selectedIndex
    };
  }

  // --------------------------------------------------
  // STEP 5G.3 — FILE RELEASE FAILURE
  // --------------------------------------------------

  function showFileReleaseFailureBanner() {
    const oldBanner =
      document.getElementById(
        "ai-guardian-banner"
      );

    if (oldBanner) {
      oldBanner.remove();
    }

    const banner =
      document.createElement(
        "div"
      );

    banner.id =
      "ai-guardian-banner";

    banner.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 2147483647;
      width: 360px;
      padding: 16px;
      border-radius: 12px;
      background: #92400e;
      color: white;
      font-family: Arial, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      box-shadow: 0 8px 30px rgba(0,0,0,0.35);
    `;

    banner.innerHTML = `
      <strong style="font-size:16px;">
        ✅ File Approved
      </strong>

      <div style="margin-top:8px;">
        The file passed the Guardian security check.
      </div>

      <div style="margin-top:10px;">
        Automatic re-attachment failed. Please select the file again
        manually using the attachment button.
      </div>

      <button
        id="ai-guardian-close"
        style="
          margin-top:12px;
          padding:6px 12px;
          border:0;
          border-radius:6px;
          cursor:pointer;
        "
      >
        Close
      </button>
    `;

    document.body.appendChild(
      banner
    );

    const closeButton =
      document.getElementById(
        "ai-guardian-close"
      );

    if (closeButton) {
      closeButton.addEventListener(
        "click",
        () => {
          banner.remove();
        }
      );
    }

    setTimeout(
      () => {
        if (banner.isConnected) {
          banner.remove();
        }
      },
      10000
    );
  }


  function releaseHeldFile() {
    if (!heldFile) {
      console.error(
        "[AI Guardian] STEP 5G.3: No held file available for ALLOW release."
      );

      showFileReleaseFailureBanner();

      return false;
    }

    const selectedInput =
      findFreshFileInput();

    if (!selectedInput) {
      console.error(
        "[AI Guardian] STEP 5G.3: No verified file input found for ALLOW release."
      );

      showFileReleaseFailureBanner();

      return false;
    }

    const selectedMarker =
      selectedInput.getAttribute(
        "data-ai-guardian-pending"
      );

    const markerMatches =
      selectedMarker ===
      heldFileInputMarker;

    console.log(
      `[AI Guardian] STEP 5G.3: Selected input marker verified: ${heldFileInputMarker} === ${selectedMarker} -> ${markerMatches ? "MATCH" : "MISMATCH"}`
    );

    /*
     * Mandatory verification:
     * Never inject into an unverified input.
     */
    if (!markerMatches) {
      console.error(
        "[AI Guardian] STEP 5G.3: No verified input found — aborting injection, showing manual re-attach banner."
      );

      showFileReleaseFailureBanner();

      return false;
    }

    try {
      const dataTransfer =
        new DataTransfer();

      dataTransfer.items.add(
        heldFile
      );

      selectedInput.files =
        dataTransfer.files;

      console.log(
        "[AI Guardian] STEP 5G.3: Proceeding with DataTransfer injection on VERIFIED input."
      );

      console.log(
        "[AI Guardian] STEP 5G.3: Re-injected file:",
        selectedInput.files.length > 0
          ? selectedInput.files[0].name
          : "(none)"
      );

      allowNextFileChange =
        true;

      selectedInput.dispatchEvent(
        new Event(
          "change",
          {
            bubbles: true
          }
        )
      );

      allowNextFileChange =
        false;

      selectedInput.removeAttribute(
        "data-ai-guardian-pending"
      );

      console.log(
        "[AI Guardian] STEP 5G.3: Synthetic change event dispatched."
      );

      return true;
    } catch (error) {
      allowNextFileChange =
        false;

      console.error(
        "[AI Guardian] STEP 5G.3: Could not re-inject approved file:",
        error
      );

      showFileReleaseFailureBanner();

      return false;
    }
  }

  // --------------------------------------------------
  // STEP 5G.4 — DRAG-AND-DROP ALLOW / BLOCK
  // --------------------------------------------------

  function showDropFailureBanner() {
    const oldBanner =
      document.getElementById(
        "ai-guardian-banner"
      );

    if (oldBanner) {
      oldBanner.remove();
    }

    const banner =
      document.createElement(
        "div"
      );

    banner.id =
      "ai-guardian-banner";

    banner.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 2147483647;
      width: 360px;
      padding: 16px;
      border-radius: 12px;
      background: #92400e;
      color: white;
      font-family: Arial, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      box-shadow: 0 8px 30px rgba(0,0,0,0.35);
    `;

    banner.innerHTML = `
      <strong style="font-size:16px;">
        ✅ File Approved
      </strong>

      <div style="margin-top:8px;">
        The file passed the Guardian security check.
      </div>

      <div style="margin-top:10px;">
        Automatic drop re-attachment failed. Please drag the file into the
        chat again manually.
      </div>

      <button
        id="ai-guardian-close"
        style="
          margin-top:12px;
          padding:6px 12px;
          border:0;
          border-radius:6px;
          cursor:pointer;
        "
      >
        Close
      </button>
    `;

    document.body.appendChild(
      banner
    );

    const closeButton =
      document.getElementById(
        "ai-guardian-close"
      );

    if (closeButton) {
      closeButton.addEventListener(
        "click",
        () => {
          banner.remove();
        }
      );
    }

    setTimeout(
      () => {
        if (banner.isConnected) {
          banner.remove();
        }
      },
      10000
    );
  }

  function findVerifiedDropTarget() {
    if (!heldDropMarker) {
      console.error(
        "[AI Guardian] STEP 5G.4: No drop marker available."
      );

      return null;
    }

    const originalConnected =
      !!heldDropTarget &&
      heldDropTarget.isConnected;

    console.log(
      "[AI Guardian] STEP 5G.4: Layer 1 — original drop target isConnected:",
      originalConnected
    );

    if (originalConnected) {
      const markerMatches =
        heldDropTarget.getAttribute(
          "data-ai-guardian-drop-pending"
        ) === heldDropMarker;

      console.log(
        "[AI Guardian] STEP 5G.4: Layer 1 — marker verified:",
        markerMatches
      );

      if (markerMatches) {
        return heldDropTarget;
      }

      console.error(
        "[AI Guardian] STEP 5G.4: Original drop target marker mismatch."
      );

      return null;
    }

    if (
      heldDropContainer &&
      heldDropContainer.isConnected
    ) {
      const candidates =
        heldDropContainer.querySelectorAll(
          "[data-ai-guardian-drop-pending]"
        );

      console.log(
        "[AI Guardian] STEP 5G.4: Layer 2 — candidates found in container scope:",
        candidates.length
      );

      for (
        const candidate
        of candidates
      ) {
        if (
          candidate.getAttribute(
            "data-ai-guardian-drop-pending"
          ) === heldDropMarker
        ) {
          console.log(
            "[AI Guardian] STEP 5G.4: Layer 2 — marker match found: true"
          );

          return candidate;
        }
      }

      console.log(
        "[AI Guardian] STEP 5G.4: Layer 2 — marker match found: false"
      );
    } else {
      console.log(
        "[AI Guardian] STEP 5G.4: Layer 2 — stable container unavailable."
      );
    }

    console.error(
      "[AI Guardian] STEP 5G.4: No verified drop target found — aborting redispatch."
    );

    return null;
  }

  // --------------------------------------------------
  // 5G.4 MINIMAL FIX — CLEAR CHATGPT DROP OVERLAY
  // --------------------------------------------------

  function clearBlockedDropOverlay() {
    if (
      !heldDropTarget ||
      !heldDropTarget.isConnected
    ) {
      console.log(
        "[AI Guardian] STEP 5G.4: Drop target unavailable for overlay cleanup."
      );

      return;
    }

    console.log(
      "[AI Guardian] STEP 5G.4: Dispatching synthetic dragleave for overlay cleanup."
    );

    const cleanupEvent =
      new DragEvent(
        "dragleave",
        {
          bubbles: true,
          cancelable: false
        }
      );

    heldDropTarget.dispatchEvent(
      cleanupEvent
    );

    console.log(
      "[AI Guardian] STEP 5G.4: Synthetic dragleave dispatched."
    );
  }

  function releaseHeldDropFile() {
    if (!heldFile) {
      console.error(
        "[AI Guardian] STEP 5G.4: No held file available for ALLOW release."
      );

      showDropFailureBanner();

      return false;
    }

    const selectedDropTarget =
      findVerifiedDropTarget();

    if (!selectedDropTarget) {
      showDropFailureBanner();

      return false;
    }

    const selectedMarker =
      selectedDropTarget.getAttribute(
        "data-ai-guardian-drop-pending"
      );

    const markerMatches =
      selectedMarker ===
      heldDropMarker;

    console.log(
      `[AI Guardian] STEP 5G.4: Selected drop target marker verified: ${heldDropMarker} === ${selectedMarker} -> ${markerMatches ? "MATCH" : "MISMATCH"}`
    );

    if (!markerMatches) {
      console.error(
        "[AI Guardian] STEP 5G.4: No verified drop target — aborting redispatch."
      );

      showDropFailureBanner();

      return false;
    }

    try {
      const dataTransfer =
        new DataTransfer();

      dataTransfer.items.add(
        heldFile
      );

      console.log(
        "[AI Guardian] STEP 5G.4: Reconstructed DataTransfer with approved file."
      );

      allowNextDrop =
        true;

      const syntheticDropEvent =
        new DragEvent(
          "drop",
          {
            bubbles: true,
            cancelable: true,
            dataTransfer
          }
        );

      console.log(
        "[AI Guardian] STEP 5G.4: Synthetic drop event isTrusted:",
        syntheticDropEvent.isTrusted
      );

      selectedDropTarget.dispatchEvent(
        syntheticDropEvent
      );

      allowNextDrop =
        false;

      selectedDropTarget.removeAttribute(
        "data-ai-guardian-drop-pending"
      );

      console.log(
        "[AI Guardian] STEP 5G.4: Synthetic drop event dispatched to VERIFIED target."
      );

      return true;
    } catch (error) {
      allowNextDrop =
        false;

      console.error(
        "[AI Guardian] STEP 5G.4: Could not redispatch approved drop:",
        error
      );

      showDropFailureBanner();

      return false;
    }
  }

  function handleFilePickerIntercept(event) {
    const target =
      event.target;

    if (
      !(target instanceof HTMLInputElement)
    ) return;

    if (
      target.type !== "file"
    ) return;

    if (
      !target.files ||
      target.files.length === 0
    ) {
      return;
    }

    if (allowNextFileChange) {
      console.log(
        "[AI Guardian] STEP 5G.3: Allowing synthetic file change to pass through."
      );

      return;
    }

    event.stopImmediatePropagation();

    if (fileScanInProgress) {
      console.warn(
        "[AI Guardian] STEP 5G.2: A file is already being scanned. New file selection ignored."
      );

      target.value = "";

      return;
    }

    const file =
      target.files[0];

    // TEMP DEBUG — remove after 5G.3 diagnosis.
    console.log(
      "[AI Guardian] TEMP DEBUG: File inputs at original interception."
    );

    const originalInputDebug =
      document.querySelectorAll(
        'input[type="file"]'
      );

    console.log(
      "[AI Guardian] TEMP DEBUG: Original file input count:",
      originalInputDebug.length
    );

    originalInputDebug.forEach(
      (
        input,
        index
      ) => {
        console.log(
          `[AI Guardian] TEMP DEBUG: original input[${index}] accept=${input.getAttribute("accept") || "(none)"} multiple=${input.hasAttribute("multiple")} sameAsEventTarget=${input === target}`
        );
      }
    );

    fileSelectionCounter +=
      1;

    heldFileInputMarker =
      `ai-guardian-file-${Date.now()}-${fileSelectionCounter}`;

    heldFileInput =
      target;

    heldFileAccept =
      target.getAttribute(
        "accept"
      ) || null;

    heldFileMultiple =
      target.hasAttribute(
        "multiple"
      );

    heldFileContainer =
      target.closest("form") ||
      target.parentElement;

    target.setAttribute(
      "data-ai-guardian-pending",
      heldFileInputMarker
    );

    console.log(
      "[AI Guardian] TEMP DEBUG: original input marker:",
      heldFileInputMarker
    );

    console.log(
      "[AI Guardian] STEP 5G.2: File-input change intercepted."
    );

    console.log(
      "[AI Guardian] STEP 5G.2: Type:",
      file.type || "unknown"
    );

    console.log(
      "[AI Guardian] STEP 5G.2: Size:",
      file.size,
      "bytes"
    );

    console.log(
      "[AI Guardian] STEP 5G.2: Original upload handler blocked."
    );

    heldFile =
      file;

    fileScanInProgress =
      true;

    target.value =
      "";

    console.log(
      "[AI Guardian] STEP 5G.2: File input cleared."
    );

    console.log(
      "[AI Guardian] STEP 5G.2: File held. Starting Guardian scan."
    );

    handleFileSelection(
      heldFile,
      (response) => {
        if (!response) {
          response = {
            decision: "INCOMPLETE",
            scan_status: "FAILED",
            risk: "UNKNOWN",
            entities: [],
            error: "No file scan result was received. The intercepted file was not released."
          };
        }

        if (
          response.decision ===
          "BLOCK"
        ) {
          console.log(
            "[AI Guardian] STEP 5G.2: Decision = BLOCK. File is held for reviewer approval."
          );

          heldFileEventId =
            response.event_id || null;

          showBanner({
            ...response,
            entities:
              response.entities || [],
            approvalMessage: response.event_id
              ? "Blocked — sent for reviewer approval. Keep this page and file input open."
              : "This file was blocked."
          });

        } else if (
          response.decision ===
          "ALLOW"
        ) {
          console.log(
            "[AI Guardian] STEP 5G.3: Decision = ALLOW. Releasing approved file."
          );

          releaseHeldFile();

        } else if (
          response.decision ===
          "REDACT"
        ) {
          console.log(
            "[AI Guardian] STEP 5H: Decision = REDACT. Original file will not be released."
          );

          showFileRedactedBanner({
            ...response,
            entities:
              response.entities || []
          });

        } else {
          console.log(
            "[AI Guardian] STEP 5G.2: Decision =",
            response.decision,
            "File remains unreleased."
          );

          showFileNotReleasedBanner({
            ...response,
            entities:
              response.entities || []
          });
        }

        if (response.decision !== "BLOCK" || response.error) {
          clearHeldFileState();

          console.log(
            "[AI Guardian] STEP 5G.2: Held file reference cleared."
          );
        }
      }
    );
  }

  /*
   * Register this capture listener BEFORE the existing file-detection
   * change listener below. That way stopImmediatePropagation() prevents
   * the existing handler from sending FILE_METADATA / FILE_UPLOAD.
   */
  document.addEventListener(
    "change",
    handleFilePickerIntercept,
    true
  );

  // File selected through the file picker
  document.addEventListener(
    "change",
    (event) => {
      const target =
        event.target;

      if (
        !(target instanceof HTMLInputElement)
      ) return;

      if (
        target.type !== "file"
      ) return;

      if (allowNextFileChange) {
        allowNextFileChange =
          false;

        console.log(
          "[AI Guardian] STEP 5G.3: Synthetic change passed through; skipping duplicate file scan."
        );

        return;
      }

      if (
        !target.files ||
        target.files.length === 0
      ) return;

      console.log(
        "[AI Guardian] File picker selection detected."
      );

      for (
        const file
        of target.files
      ) {
        handleFileSelection(
          file
        );
      }
    },
    true
  );

  // --------------------------------------------------
  // STEP 5G.4 — DRAG-AND-DROP FILE ENFORCEMENT
  //
  // No dragenter / dragover / dragleave listeners.
  // The site's existing dragover behavior remains untouched.
  // --------------------------------------------------
  document.addEventListener(
    "drop",
    (event) => {
      if (allowNextDrop) {
        allowNextDrop =
          false;

        console.log(
          "[AI Guardian] STEP 5G.4: Synthetic drop passed through; skipping duplicate file scan."
        );

        return;
      }

      if (
        !event.dataTransfer ||
        event.dataTransfer.files.length === 0
      ) {
        return;
      }

      event.preventDefault();

      event.stopImmediatePropagation();

      const files =
        event.dataTransfer.files;

      if (files.length > 1) {
        console.warn(
          "[AI Guardian] STEP 5G.4: Multiple files dropped. Only the first file will be scanned in this step."
        );
      }

      const file =
        files[0];

      if (fileScanInProgress) {
        console.warn(
          "[AI Guardian] STEP 5G.4: A file is already being scanned. New drop ignored."
        );

        return;
      }

      const dropTarget =
        event.target instanceof Element
          ? event.target
          : null;

      if (!dropTarget) {
        console.error(
          "[AI Guardian] STEP 5G.4: Drop target is not a DOM Element. Cannot safely continue."
        );

        showDropFailureBanner();

        return;
      }

      heldFile =
        file;

      heldDropTarget =
        dropTarget;

      heldDropContainer =
        dropTarget.closest(
          "form"
        ) ||
        dropTarget.parentElement;

      heldDropMarker =
        `ai-guardian-drop-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

      dropTarget.setAttribute(
        "data-ai-guardian-drop-pending",
        heldDropMarker
      );

      fileScanInProgress =
        true;

      console.log(
        "[AI Guardian] STEP 5G.4: Drop intercepted."
      );

      console.log(
        "[AI Guardian] STEP 5G.4: Captured file:",
        file.name
      );

      console.log(
        "[AI Guardian] STEP 5G.4: Type:",
        file.type || "unknown"
      );

      console.log(
        "[AI Guardian] STEP 5G.4: Size:",
        file.size,
        "bytes"
      );

      console.log(
        "[AI Guardian] STEP 5G.4: Original drop handler blocked."
      );

      console.log(
        "[AI Guardian] STEP 5G.4: File is held. Starting Guardian scan."
      );

      handleFileSelection(
        heldFile,
        (response) => {
          if (!response) {
            response = {
              decision: "INCOMPLETE",
              scan_status: "FAILED",
              risk: "UNKNOWN",
              entities: [],
              error: "No scan result was received. The intercepted dropped file was not released."
            };
          }

          if (
            response.decision ===
            "BLOCK"
          ) {
            console.log(
              "[AI Guardian] STEP 5G.4: Decision = BLOCK. Dropped file will not be released."
            );

            heldDropEventId =
              response.event_id || null;

            showBanner({
              ...response,
              entities:
                response.entities || [],
              approvalMessage: response.event_id
                ? "Blocked — sent for reviewer approval. Keep this page open."
                : "This file was blocked."
            });

            clearBlockedDropOverlay();

            if (
              heldDropTarget &&
              heldDropTarget.isConnected
            ) {
              heldDropTarget.removeAttribute(
                "data-ai-guardian-drop-pending"
              );
            }

          } else if (
            response.decision ===
            "ALLOW"
          ) {
            console.log(
              "[AI Guardian] STEP 5G.4: Decision = ALLOW. Releasing approved dropped file."
            );

            releaseHeldDropFile();

          } else if (
            response.decision ===
            "REDACT"
          ) {
            console.log(
              "[AI Guardian] STEP 5H: Decision = REDACT. Original dropped file will not be released."
            );

            showFileRedactedBanner({
              ...response,
              entities:
                response.entities || []
            });

            clearBlockedDropOverlay();

          } else {
            console.log(
              "[AI Guardian] STEP 5G.4: Decision =",
              response.decision,
              "Dropped file remains unreleased."
            );

            showFileNotReleasedBanner({
              ...response,
              entities:
                response.entities || []
            });
          }

          if (response.decision !== "BLOCK" || response.error) {
            clearHeldDropState();

            console.log(
              "[AI Guardian] STEP 5G.4: Held dropped file reference cleared."
            );
          }
        }
      );
    },
    true
  );

})();
