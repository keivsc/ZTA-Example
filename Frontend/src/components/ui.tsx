
interface FormProps {
  onSubmit: () => void;
  redirect: () => void;
  message: string;
}

export function GlassButton({ text, onClick }: { text: string; onClick: () => void }) {
  return (
    <button className="btn-glass" onClick={onClick}>
      {text}
    </button>
  );
}

export function SignUpForm({ onSubmit, redirect, message }: FormProps) {
  return (
    <div className="form-card">
      <h1>Secure Site</h1>
      <div className="side-div">
        <div>
          <label>First Name</label>
          <input id="firstname" type="text" placeholder="John" required />
        </div>
        <div>
          <label>Last Name</label>
          <input id="lastname" type="text" placeholder="Doe" required />
        </div>
      </div>
      <label>Email</label>
      <input id="email" type="email" placeholder="example@example.com" required />
      <label>Password</label>
      <input id="password" type="password" placeholder="Password" required />
      <p id="message" className="mt-4 text-center">{message}</p>
      <div className="side-div">
        <button className="btn-glass" type="button" onClick={redirect}>Login</button>
        <button className="btn-glass" type="button" onClick={onSubmit}>Sign Up</button>
      </div>
      
    </div>
  );
}

export function LoginForm({ onSubmit, redirect, message }: FormProps) {
  return (
    <div className="form-card">
      <h1>Secure Site</h1>
      <label>Email</label>
      <input id="email" type="email" placeholder="example@example.com" required />
      <label>Password</label>
      <input id="password" type="password" placeholder="Password" required />
      <p id="message" className="mt-4 text-center">{message}</p>
      <div className="side-div">
        <button className="btn-glass" type="button" onClick={redirect}>Sign Up</button>
        <button className="btn-glass" type="submit" onClick={onSubmit}>Login</button>
      </div>
    </div>
  );
}


