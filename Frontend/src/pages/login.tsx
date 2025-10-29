import { useNavigate } from "react-router-dom";
import { navigateTo } from "../utils/navigate";
import { useEffect, useState } from "react";
import { getPasswordSalt, verifyChallenge, verifyHash, verifyTOTP } from "../utils/api";
import { decryptRSA, deriveKey, fromBase64, hashPassword } from "../utils/crypto";
import { LoginForm, SignUpForm } from "../components/ui";

interface TOTPInputProps{
    userId: string;
    TOTPExpiry: number;
}

function Login(){
    const [loading, setLoading] = useState(false);
    const [message, setMessage] = useState("");
    const [showTOTPInput, setTOTPInput] = useState(false);
    const [userId, setUserId] = useState<string | null>(null);
    const [expiresAt, setExpiresAt] = useState<number | null>(null);

    const navigate = useNavigate();

    const signUpRedirect = () =>{
        navigateTo(navigate, '/register')
    }

    const loginButtonClicked = async ()=>{
        setLoading(true);
        setMessage("");

        const email = (document.getElementById("email") as HTMLInputElement).value;
        const password = (document.getElementById("password") as HTMLInputElement).value;

        const passwordSalt = await (await getPasswordSalt(email)).json();
        console.log(passwordSalt);
        const saltBytes = fromBase64(passwordSalt.data.passwordSalt);
        const hashedPassword = await hashPassword(password, saltBytes);


        const challengeFetch = await verifyHash(email, hashedPassword.hash);
        const challengeRecord = (await challengeFetch.json()).data;
        console.log(challengeRecord);

        const derivedKey = await deriveKey(password, challengeRecord.salt, challengeRecord.iv, challengeRecord.key)
        if (derivedKey.rawPrivateKey){
            const decryptedChallenge = await decryptRSA(derivedKey.rawPrivateKey, challengeRecord.challengeText)
            const challengeResult = await verifyChallenge(challengeRecord.userId, decryptedChallenge);
            const challengeJson = await challengeResult.json();
            if (challengeResult.status == 200){
                setTOTPInput(true);
                setUserId(challengeRecord.userId);
                setExpiresAt(challengeJson.data.TOTPExpiry)
            }
        }

    }

    if (showTOTPInput && userId && expiresAt) {
        return <TOTPInput userId={userId} TOTPExpiry={expiresAt} />;
    }


    return (<div>
        <LoginForm onSubmit={loginButtonClicked} redirect={signUpRedirect} message={message}/>

    </div>);
}

export function TOTPInput({ userId, TOTPExpiry }: TOTPInputProps) {
  const [timeLeft, setTimeLeft] = useState(0);

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
      console.log("COMPLETE!");
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