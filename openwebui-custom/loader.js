(() => {
  const INSTALL_URL = "http://10.91.9.234:3002/downloads/windows-browser-agent.ps1";

  function mountInstallButton() {
    if (document.getElementById("qualys-pilot-agent-cta")) {
      return;
    }

    const shell = document.createElement("div");
    shell.id = "qualys-pilot-agent-cta";
    shell.innerHTML = `
      <button class="qualys-pilot-agent-launcher" type="button" aria-expanded="false">
        <span class="qualys-pilot-agent-launcher-dot"></span>
        <span>Agent</span>
      </button>
      <div class="qualys-pilot-agent-card" hidden>
        <div class="qualys-pilot-agent-eyebrow">Pilot</div>
        <div class="qualys-pilot-agent-title">Windows Telemetry Agent</div>
        <div class="qualys-pilot-agent-copy">Install the approved endpoint collector for browser and device activity.</div>
        <div class="qualys-pilot-agent-actions">
          <a class="qualys-pilot-agent-button" href="${INSTALL_URL}">Install Now</a>
          <button class="qualys-pilot-agent-close" type="button" aria-label="Close">Later</button>
        </div>
      </div>
    `;

    const launcher = shell.querySelector(".qualys-pilot-agent-launcher");
    const card = shell.querySelector(".qualys-pilot-agent-card");
    const closeButton = shell.querySelector(".qualys-pilot-agent-close");

    const openCard = () => {
      shell.classList.add("is-open");
      card.hidden = false;
      launcher.setAttribute("aria-expanded", "true");
    };

    const closeCard = () => {
      shell.classList.remove("is-open");
      card.hidden = true;
      launcher.setAttribute("aria-expanded", "false");
    };

    launcher.addEventListener("click", () => {
      if (shell.classList.contains("is-open")) {
        closeCard();
        return;
      }
      openCard();
    });

    closeButton.addEventListener("click", closeCard);
    document.body.appendChild(shell);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mountInstallButton, { once: true });
  } else {
    mountInstallButton();
  }
})();
