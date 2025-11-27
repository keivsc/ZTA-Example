import { useState, useEffect } from "react";
import { register as registerUser } from "../controllers/registerController";
import { navigateTo } from "../utils/navigate";
import { QRCodeSVG } from "qrcode.react";
import { useNavigate } from "react-router-dom";
import { LoginForm, SignUpForm } from "../components/ui";

interface TOTPRegisterProps {
  otpAuthUrl: string;
}

function Register() {
    const navigate = useNavigate();

    const loginRedirect = () =>{
      navigateTo(navigate, '/login');
    }

    const [loading, setLoading] = useState(false);
    const [message, setMessage] = useState("");
    const [showTOTP, setShowTOTP] = useState(false);
    const [OTPauthURL, setOtpAuthUrl] = useState<string | null>(null);

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
    console.log(1);
    try {
        const result = await registerUser(fullName, email, password);

        if (result.code == 200) {
            setOtpAuthUrl(result.data?.otpauthURL);
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

    if (showTOTP && OTPauthURL) {
        return <TOTPRegister otpAuthUrl={OTPauthURL} />;
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


function TOTPRegister({ otpAuthUrl }: TOTPRegisterProps) {
  const navigate = useNavigate();

  const continueButton = () =>{
    
    navigateTo(navigate, '/login')
  }

  return (
    <div>
      <p id="text">Scan this QR code with your authenticator app:</p>
      {otpAuthUrl && <QRCodeSVG value={otpAuthUrl} size={200} />}
      <p id="text">
      Enter code manually instead: {otpAuthUrl ? otpAuthUrl.split("secret=")[1].split("&")[0] : ""}
      </p>
      <br></br>
      <button id="continue" onClick={continueButton}>Continue</button>
    </div>
  );
}


export default Register;
