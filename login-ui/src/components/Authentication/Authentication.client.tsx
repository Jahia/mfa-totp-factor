import { useState } from "react";
import LoginForm from "./LoginForm.client";
import { ApiRootContext } from "../../hooks/ApiRootContext";
import TotpCodeVerificationForm from "./TotpCodeVerificationForm.client";
import EmailCodeVerificationForm from "./EmailCodeVerificationForm.client";
import WebauthnVerificationForm from "./WebauthnVerificationForm.client";
import FactorChooser from "./FactorChooser.client";
import EnrollmentChooser from "./EnrollmentChooser.client";
import TotpEnrollmentForm from "./TotpEnrollmentForm.client";
import WebauthnRegistrationForm from "./WebauthnRegistrationForm.client";
import type { Props } from "./types";
import { redirect, sessionFactors } from "../../services";
import FatalErrorScreen from "./FatalErrorScreen.client";
import type { MfaError } from "../../services/common";

enum Step {
  LOGIN,
  CHOOSE_FACTOR,
  VERIFY,
  ENROLL,
  COMPLETE,
  FATAL_ERROR,
}

export default function Authentication({
  apiRoot,
  content,
}: Readonly<{
  apiRoot: string;
  content: Props;
}>) {
  const [step, setStep] = useState<Step>(Step.LOGIN);
  const [fatalError, setFatalError] = useState<MfaError | undefined>(undefined);
  const [availableFactors, setAvailableFactors] = useState<string[]>([]);
  const [activeFactor, setActiveFactor] = useState<string | null>(null);
  const [enrollableFactors, setEnrollableFactors] = useState<string[]>([]);
  const [enrollFactor, setEnrollFactor] = useState<string | null>(null);

  /**
   * A factor finished (verified or drained). With other factors still required, continue the
   * flow — pick-one enforcement makes the leftovers skip server-side, so they drain quickly.
   * With nothing left, the session is complete and the auth cookie is set: leave.
   */
  const onFactorCompleted = (remainingFactors: string[]) => {
    if (remainingFactors.length === 0) {
      setStep(Step.COMPLETE);
      redirect(content.contextPath);
      return;
    }
    setAvailableFactors(remainingFactors);
    setActiveFactor(remainingFactors[0]);
    setStep(Step.VERIFY);
  };

  const onResetFlow = () => {
    setStep(Step.LOGIN);
    setFatalError(undefined);
    setAvailableFactors([]);
    setActiveFactor(null);
    setEnrollableFactors([]);
    setEnrollFactor(null);
  };

  const onLoginSuccess = async ({ remainingFactors }: { username: string; remainingFactors: string[] }) => {
    setAvailableFactors(remainingFactors);
    if (remainingFactors.length === 1) {
      // Skip the chooser when there's only one option.
      setActiveFactor(remainingFactors[0]);
      setStep(Step.VERIFY);
      return;
    }
    // Several factors are enabled platform-wide, but the chooser must only offer the ones THIS
    // user configured: an unconfigured factor is a dead end (its pick-one row defers to a
    // configured sibling, and the user lands on a different factor than the one they picked).
    // On query failure fall back to the unfiltered list — the chooser is cosmetic, verification
    // stays enforced server-side.
    const configured = await sessionFactors(apiRoot);
    const offer =
      configured === null ? remainingFactors : remainingFactors.filter((f) => configured.includes(f));
    if (offer.length === 0) {
      // Nothing configured yet: walk the required factors — the first prepare routes to
      // inline enrollment (enrollment_required), where the ENROLLMENT chooser takes over.
      setActiveFactor(remainingFactors[0]);
      setStep(Step.VERIFY);
    } else if (offer.length === 1) {
      setActiveFactor(offer[0]);
      setStep(Step.VERIFY);
    } else {
      setAvailableFactors(offer);
      setStep(Step.CHOOSE_FACTOR);
    }
  };

  const onFactorPicked = (factor: string) => {
    setActiveFactor(factor);
    setStep(Step.VERIFY);
  };

  const onFatalError = (error: MfaError) => {
    setFatalError(error);
    setStep(Step.FATAL_ERROR);
  };

  /**
   * Enforcement is active but the user has none of the enforced factors configured: switch to
   * inline enrollment. The server lists the factors the user may set up (enforced ∩ enabled on
   * this site) in the error's `enrollableFactors` argument.
   */
  const onEnrollmentRequired = (error: MfaError) => {
    const offer = error.arguments?.find((a) => a.name === "enrollableFactors")?.value ?? "";
    const factors = offer.split(",").map((f) => f.trim()).filter(Boolean);
    const fallback = activeFactor ? [activeFactor] : [];
    const offered = factors.length > 0 ? factors : fallback;
    if (offered.length === 0) {
      onFatalError(error);
      return;
    }
    setEnrollableFactors(offered);
    setEnrollFactor(offered.length === 1 ? offered[0] : null);
    setStep(Step.ENROLL);
  };

  const onEnrollFactorPicked = (factor: string) => {
    setEnrollFactor(factor);
  };

  // Dispatch to the right verification form. Unknown factor types fall back to a
  // FatalErrorScreen with a clear error code so the user can restart cleanly.
  const renderVerificationForm = () => {
    switch (activeFactor) {
      case "totp":
        return (
          <TotpCodeVerificationForm
            content={content}
            onSuccess={onFactorCompleted}
            onEnrollmentRequired={onEnrollmentRequired}
            onFatalError={onFatalError}
          />
        );
      case "email_code":
        return <EmailCodeVerificationForm onSuccess={onFactorCompleted} onFatalError={onFatalError} />;
      case "webauthn":
        return (
          <WebauthnVerificationForm
            content={content}
            onSuccess={onFactorCompleted}
            onEnrollmentRequired={onEnrollmentRequired}
            onFatalError={onFatalError}
          />
        );
      default:
        return (
          <FatalErrorScreen
            error={{ code: "factor_type_not_supported", arguments: [{ name: "factorType", value: activeFactor ?? "" }] }}
            onResetFlow={onResetFlow}
          />
        );
    }
  };

  // Inline enrollment: a chooser when several factors are offered, then the factor's setup form.
  const renderEnrollment = () => {
    if (!enrollFactor) {
      return <EnrollmentChooser factors={enrollableFactors} onSelect={onEnrollFactorPicked} />;
    }
    switch (enrollFactor) {
      case "totp":
        return <TotpEnrollmentForm onComplete={onFactorCompleted} onFatalError={onFatalError} />;
      case "webauthn":
        return <WebauthnRegistrationForm onComplete={onFactorCompleted} onFatalError={onFatalError} />;
      default:
        return (
          <FatalErrorScreen
            error={{ code: "factor_type_not_supported", arguments: [{ name: "factorType", value: enrollFactor }] }}
            onResetFlow={onResetFlow}
          />
        );
    }
  };

  return (
    <ApiRootContext value={apiRoot}>
      {step === Step.FATAL_ERROR && fatalError && (
        <FatalErrorScreen error={fatalError} onResetFlow={onResetFlow} />
      )}
      {step === Step.LOGIN && (
        <LoginForm
          content={content}
          onSuccess={onLoginSuccess}
          onAllFactorsCompleted={() => onFactorCompleted([])}
          onFatalError={onFatalError}
        />
      )}
      {step === Step.CHOOSE_FACTOR && (
        <FactorChooser factors={availableFactors} onSelect={onFactorPicked} />
      )}
      {step === Step.VERIFY && renderVerificationForm()}
      {step === Step.ENROLL && renderEnrollment()}
    </ApiRootContext>
  );
}
