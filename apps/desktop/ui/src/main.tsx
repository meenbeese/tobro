import React from "react";
import ReactDOM from "react-dom/client";
import { getCurrentWindow } from "@tauri-apps/api/window";
import App from "./App";
import { About } from "./About";
import { Settings } from "./Settings";
import { initTheme } from "./theme";
import "./styles.css";

initTheme();

const windowKind = new URLSearchParams(window.location.search).get("window");

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    {windowKind === "settings" ? (
      <main className="app settings-window">
        <Settings
          onClose={() => void getCurrentWindow().close()}
        />
      </main>
    ) : windowKind === "about" ? (
      <main className="app about-window">
        <About
          onClose={() => void getCurrentWindow().close()}
        />
      </main>
    ) : (
      <App />
    )}
  </React.StrictMode>,
);
