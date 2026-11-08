import React from "react";
import ReactDOM from "react-dom/client";
import { getCurrentWindow } from "@tauri-apps/api/window";
import App from "./App";
import { Settings } from "./Settings";
import "./styles.css";

const isSettingsWindow =
  new URLSearchParams(window.location.search).get("window") === "settings";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    {isSettingsWindow ? (
      <main className="app settings-window">
        <Settings
          onClose={() => void getCurrentWindow().close()}
        />
      </main>
    ) : (
      <App />
    )}
  </React.StrictMode>,
);
