import { useCallback, useState } from "react";

interface CopyButtonProps {
  text: string;
  label?: string;
  copiedLabel?: string;
  title?: string;
  className?: string;
  disabled?: boolean;
}

export function CopyButton({
  text,
  label = "Copy",
  copiedLabel = "Copied!",
  title,
  className = "",
  disabled = false,
}: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    if (disabled || !text) return;
    try {
      if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        await navigator.clipboard.writeText(text);
      } else {
        // Fallback for older environments
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch (err) {
      // Ignore copy errors silently
      console.error("Failed to copy:", err);
    }
  }, [text, disabled]);

  return (
    <button
      type="button"
      className={`copy-btn ${copied ? "copy-btn-copied" : ""} ${className}`}
      onClick={handleCopy}
      disabled={disabled || !text}
      title={title || (copied ? copiedLabel : label)}
      aria-label={copied ? copiedLabel : label}
    >
      {copied ? copiedLabel : label}
    </button>
  );
}

export default CopyButton;
