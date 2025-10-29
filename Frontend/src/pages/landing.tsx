import { useNavigate } from "react-router-dom";
import { GlassButton } from "../components/ui";
import { navigateTo } from "../utils/navigate"; // make sure the path is correct

function Landing() {
  const navigate = useNavigate(); // ✅ hook at top level

  return (
    <GlassButton text="Login" onClick={() => navigateTo(navigate, '/login')} /> // ✅ wrapped in arrow function
  );
}

export default Landing;