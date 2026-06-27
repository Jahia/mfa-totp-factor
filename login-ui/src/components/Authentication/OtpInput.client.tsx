import { type ClipboardEvent, type KeyboardEvent, useEffect, useRef } from "react";
import classes from "./component.module.css";

interface OtpInputProps {
  /** Number of digit boxes (e.g. 6). */
  length: number;
  /** The current value as a left-packed digit string (length 0..length). */
  value: string;
  /** Called with the new left-packed digit string whenever it changes. */
  onChange: (value: string) => void;
  /** Called once the value reaches {@link length} digits (drives auto-verify). */
  onComplete?: (value: string) => void;
  disabled?: boolean;
  /** Focus the first box on mount (used when the step becomes interactive). */
  autoFocus?: boolean;
  /** Accessible name for the whole group (role="group"). */
  groupLabel: string;
  /** Accessible name for one box, e.g. (index, count) => "Digit 2 of 6". */
  digitLabel: (index: number, count: number) => string;
  /** id of the associated error container (wired as aria-describedby on the group). */
  describedById?: string;
  /** data-testid for the group; each box gets `${testId}-${i}` (0-based). */
  testId: string;
}

/**
 * Accessible segmented one-time-code input: one box per digit, auto-advance on entry,
 * Backspace/Arrow navigation, paste-distribute across all boxes, and an onComplete callback
 * once every box is filled (so the caller can auto-verify). The model is a single left-packed
 * digit string so callers keep a plain `code` value for submission.
 *
 * Accessibility (WCAG 2.2 AAA): role="group" with an accessible name, a per-box aria-label
 * ("Digit N of M"), inputMode numeric for the right mobile keypad, 44px minimum target size,
 * and the visible focus ring from the shared stylesheet.
 */
export default function OtpInput(props: Readonly<OtpInputProps>) {
  const {
    length, value, onChange, onComplete, disabled, autoFocus,
    groupLabel, digitLabel, describedById, testId,
  } = props;
  const refs = useRef<Array<HTMLInputElement | null>>([]);

  useEffect(() => {
    if (autoFocus && !disabled) {
      refs.current[0]?.focus();
    }
    // Focus the first box once, when the segmented input first becomes interactive.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /** The value as a fixed-length array of single chars ("" for empty boxes). */
  const toArray = (): string[] => Array.from({ length }, (_, i) => value[i] ?? "");

  const focusBox = (index: number) => {
    const target = Math.max(0, Math.min(index, length - 1));
    const box = refs.current[target];
    box?.focus();
    box?.select();
  };

  const commit = (next: string, focusIndex: number) => {
    onChange(next);
    focusBox(focusIndex);
    if (next.length === length) {
      onComplete?.(next);
    }
  };

  const handleChange = (index: number, raw: string) => {
    const digits = raw.replace(/\D/g, "");
    const arr = toArray();
    if (digits.length === 0) {
      // Box cleared by editing (Backspace is handled in handleKeyDown).
      arr[index] = "";
      onChange(arr.join(""));
      return;
    }
    // Distribute the entered digit(s) starting at this box (handles a single keystroke
    // and a multi-digit autofill landing in one box).
    let i = index;
    for (const digit of digits) {
      if (i >= length) {
        break;
      }
      arr[i] = digit;
      i += 1;
    }
    commit(arr.join(""), i);
  };

  const handleKeyDown = (index: number, e: KeyboardEvent<HTMLInputElement>) => {
    const arr = toArray();
    if (e.key === "Backspace") {
      e.preventDefault();
      if (arr[index]) {
        arr[index] = "";
        onChange(arr.join(""));
      } else if (index > 0) {
        arr[index - 1] = "";
        onChange(arr.join(""));
        focusBox(index - 1);
      }
    } else if (e.key === "ArrowLeft" && index > 0) {
      e.preventDefault();
      focusBox(index - 1);
    } else if (e.key === "ArrowRight" && index < length - 1) {
      e.preventDefault();
      focusBox(index + 1);
    }
  };

  const handlePaste = (e: ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const digits = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, length);
    if (digits.length === 0) {
      return;
    }
    commit(digits, digits.length);
  };

  return (
    <div
      role="group"
      aria-label={groupLabel}
      aria-describedby={describedById}
      className={classes.otpGroup}
      data-testid={testId}
    >
      {Array.from({ length }, (_, i) => (
        <input
          key={i}
          ref={(el) => {
            refs.current[i] = el;
          }}
          type="text"
          inputMode="numeric"
          autoComplete={i === 0 ? "one-time-code" : "off"}
          pattern="[0-9]*"
          maxLength={1}
          value={value[i] ?? ""}
          disabled={disabled}
          aria-label={digitLabel(i + 1, length)}
          data-testid={`${testId}-${i}`}
          className={classes.otpDigit}
          onChange={(e) => handleChange(i, e.target.value)}
          onKeyDown={(e) => handleKeyDown(i, e)}
          onPaste={handlePaste}
          onFocus={(e) => e.target.select()}
        />
      ))}
    </div>
  );
}
