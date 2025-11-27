import { useNavigate } from "react-router-dom";
import { navigateTo } from "../utils/navigate";
import { useEffect, useState } from "react";
import { LoginForm, SignUpForm } from "../components/ui";
import { login as loginUser } from "../controllers/loginController";
import { getDeviceKeys } from "../utils/crypto";
import { verifyTOTP } from "../utils/api";

interface TOTPInputProps{
    TOTPExpiry: number;
    userId: string;
}

function Login(){
    const [loading, setLoading] = useState(false);
    const [message, setMessage] = useState("");
    const [showTOTPInput, setTOTPInput] = useState(false);
    const [userId, setUserId] = useState<string | null>(null);
    const [expiresAt, setExpiresAt] = useState<number | null>(null);

    const navigate = useNavigate();

    const signUpRedirect = () =>{
        navigateTo(navigate, '/register');
    }

    const loginButtonClicked = async ()=>{
        setLoading(true);
        setMessage("");

        const email = (document.getElementById("email") as HTMLInputElement).value;
        const password = (document.getElementById("password") as HTMLInputElement).value;
        const loginRes = await loginUser(email, password);

        switch (loginRes.code) {
          case 401:
            setUserId(loginRes.userId);
            setExpiresAt(loginRes.expiresAt);
            setTOTPInput(true);
            break;

          case 200:
            navigateTo(navigate, '/explorer');
            break;

          default:
            setMessage(loginRes.message);
            break;
        }
    }

    if (showTOTPInput && expiresAt && userId) {
        return <TOTPInput TOTPExpiry={expiresAt} userId={userId}  />;
    }


    return (<div>
        <LoginForm onSubmit={loginButtonClicked} redirect={signUpRedirect} message={message}/>

    </div>);
}

export function TOTPInput({ TOTPExpiry, userId }: TOTPInputProps) {
  const [timeLeft, setTimeLeft] = useState(0);
  const navigate = useNavigate();

  useEffect(() => {
    const interval = setInterval(() => {
      const now = Date.now();
      const diff = Math.max(0, TOTPExpiry - now);
      setTimeLeft(Math.floor(diff / 1000)); // seconds left
    }, 1000);

    return () => clearInterval(interval);
  }, [TOTPExpiry]);

  const formatTime = (seconds: number) => {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m}:${s.toString().padStart(2, "0")}`;
  };

  const verifyButtonClicked = async () => {
    const code = (document.getElementById("totp") as HTMLInputElement).value;
    const resTOTP = await verifyTOTP(userId, Number.parseInt(code));
    if (resTOTP.status === 200) {
      navigateTo(navigate, '/explorer');
      return
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
      <div style={{ display: "flex", gap: "8px", marginBottom: "8px" }}>
        <input
          id="totp"
          type="number"
          placeholder="Enter 6-digit TOTP"
          maxLength={6}
          style={{
            textAlign: "center",
            width: "120px",
            letterSpacing: "4px",
            fontSize: "1.2rem",
          }}
        />
      </div>

      <div style={{ marginBottom: "8px", fontFamily: "monospace", fontSize: "1rem" }}>
        ⏳ Expires in: {formatTime(timeLeft)}
      </div>

      <button onClick={verifyButtonClicked}>Verify</button>
    </div>
  );
}



export default Login;