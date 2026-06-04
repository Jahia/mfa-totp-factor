import type { KeyboardEvent } from "react";

/**
 * Build an `onKeyDown` handler that submits a form when Enter is pressed.
 *
 * Native HTML "implicit submission" fires Enter through the form's <i>default</i> submit
 * button — but the browser skips it entirely when that button is {@code disabled}, which is
 * exactly the state of the verification forms while the code is still being typed (and, for a
 * fraction of a render, just as the last character lands). That makes Enter feel broken.
 *
 * Handling Enter on the field itself removes the dependency on the default-button state.
 * {@code preventDefault()} suppresses the browser's own implicit submission so that, in the
 * cases where it <i>would</i> have fired, {@code submit} is still invoked exactly once.
 *
 * The {@code submit} callback is expected to apply its own validity/in-flight guards, so
 * pressing Enter on an incomplete or already-submitting form is a safe no-op.
 */
export function submitOnEnter(submit: () => void) {
  return (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Enter") {
      event.preventDefault();
      submit();
    }
  };
}
