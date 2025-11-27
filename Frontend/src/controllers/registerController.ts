import { get, post, registerUser } from "../utils/api";

interface registerResult{
    code: number;
    message?: any;
    data?:any;
}

export async function register(fullName: string, email: string, password: string) : Promise<registerResult> {
  password = password.trim();
  const pattern = new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$');
  if(!pattern.test(password)){
    return {code: 400, message: "Password Needs to be at least 12 characters long and have special characters such as '!@#$%^&*()'"};
  }
  const emailPattern = new RegExp('^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$');
  if (!emailPattern.test(email)) {
    return { code: 400, message: "Please enter a valid email address." };
  }



  const userData = {
    "username": fullName,
    "email": email,
    "password":password,
  }
  const regUser = await registerUser(userData);
  console.log(regUser.status)
  if(regUser.status == 400){
    return {code:400, message:(await regUser.json()).error}
  }
  return {code: regUser.status, data:(await regUser.json())}
}