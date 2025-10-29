import { useState, useEffect } from "react";
import { getTOTPSecret, Register as RegisterUser } from "../controllers/registerController";
import { navigateTo } from "../utils/navigate";
import { QRCodeSVG } from "qrcode.react";
import { useNavigate } from "react-router-dom";
import { LoginForm, SignUpForm } from "../components/ui";

interface TOTPRegisterProps {
  email: string;
  privateKey: CryptoKey;
}

function Register() {
    const navigate = useNavigate();

    const loginRedirect = () =>{
      navigateTo(navigate, '/login');
    }

    const [loading, setLoading] = useState(false);
    const [message, setMessage] = useState("");
    const [showTOTP, setShowTOTP] = useState(false);
    const [userEmail, setUserEmail] = useState<string | null>(null);
    const [privateKey, setPrivateKeyArray] = useState<CryptoKey | null>(null);

    const registerButtonClicked = async () => {
    setLoading(true);
    setMessage("");

    const firstName = (document.getElementById("firstname") as HTMLInputElement).value;
    const lastName = (document.getElementById("lastname") as HTMLInputElement).value;
    const fullName = `${firstName} ${lastName}`
    const email = (document.getElementById("email") as HTMLInputElement).value;
    const password = (document.getElementById("password") as HTMLInputElement).value;

    if (!firstName || !lastName || !email || !password) {
      setMessage("Please enter all fields!");
      return;
    }

    try {
        const result = await RegisterUser(fullName, email, password);

        if (result.code === 201 && result.privateKey) {
            setUserEmail(email);
            setPrivateKeyArray(result.privateKey);
            setShowTOTP(true);
        } else {
            setMessage(`${result.message}`);
        }
    } catch (err) {
        console.error(err);
        setMessage("Unexpected error occurred.");
    } finally {
        setLoading(false);
    }
    };


    const showPasswordButtonClicked = () => {
    const input = document.getElementById('password') as HTMLInputElement | null;
    if (input) {
        input.type = input.type === 'password' ? 'text' : 'password'; // toggle
    }
    };

    if (showTOTP && userEmail && privateKey) {
        return <TOTPRegister email={userEmail} privateKey={privateKey} />;
    }

    if (message){
      const paragraphEl = document.getElementById('message') as HTMLParagraphElement
      paragraphEl.textContent = message
    }

    return (
    <div className="flex flex-col items-center mt-10">
        <SignUpForm onSubmit={registerButtonClicked} redirect={loginRedirect} message={message}/>
    </div>
    );
}


function TOTPRegister({ email, privateKey }: TOTPRegisterProps) {
  const [otpAuthUrl, setOtpAuthUrl] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    async function fetchSecret() {
      try {
        const url = await getTOTPSecret(email, privateKey);
        if (!url){
            document.getElementById("text")!.innerHTML="An Error Occurred, Please Contact Administrator"
        }
        setOtpAuthUrl(url);
      } catch (err) {
        console.error("Failed to get TOTP secret:", err);
      }
    }

    fetchSecret();
  }, [email, privateKey]);

  const continueButton = () =>{
    
    navigateTo(navigate, '/login')
  }

  return (
    <div>
      <p id="text">Scan this QR code with your authenticator app:</p>
      {otpAuthUrl && <QRCodeSVG value={otpAuthUrl} size={200} />}
      <button id="continue" onClick={continueButton}>Continue</button>
    </div>
  );
}


export default Register;
