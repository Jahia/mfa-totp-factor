import { Trans, useTranslation } from "react-i18next";
import classes from "./component.module.css";

interface FactorChooserProps {
  factors: string[];
  onSelect: (factor: string) => void;
}

/**
 * Renders a button per available factor. Used only when initiate() reports more than
 * one remaining factor — with a single factor, Authentication.client.tsx skips this
 * step and dispatches straight to the matching verification form.
 *
 * Currently recognises `totp` and `email_code`. Any other factor falls back to a
 * generic label keyed on the factor name (so a new factor type added to UPA shows up
 * with a usable button even before localisation is in place).
 */
export default function FactorChooser({
  factors,
  onSelect,
}: Readonly<FactorChooserProps>) {
  const { t } = useTranslation();

  const labelFor = (factor: string): string => {
    switch (factor) {
      case "totp":
        return t("factorChooser.totp");
      case "email_code":
        return t("factorChooser.email_code");
      case "webauthn":
        return t("factorChooser.webauthn");
      default:
        return factor;
    }
  };

  return (
    <div className={classes.otpFormWrapper}>
      <h2>
        <Trans i18nKey="factorChooser.title" />
      </h2>
      <p className={classes.helpText}>
        <Trans i18nKey="factorChooser.description" />
      </p>
      <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", marginTop: "1rem" }}>
        {factors.map((factor) => (
          <button
            key={factor}
            type="button"
            data-testid={`factor-choose-${factor}`}
            className={classes.submitButton}
            onClick={() => onSelect(factor)}
          >
            {labelFor(factor)}
          </button>
        ))}
      </div>
    </div>
  );
}
