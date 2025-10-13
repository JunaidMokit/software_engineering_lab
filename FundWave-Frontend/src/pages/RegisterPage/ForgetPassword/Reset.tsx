import React, { useState } from "react";
import { useLocation, Link } from "react-router-dom";
import api from "../../../util/api";

export default function Reset() {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordReset, setPasswordReset] = useState(false);
  const [error, setError] = useState(null);
  const location = useLocation();

  const done = location.state ? location.state.done : 0;
  const username = location.state ? location.state.username : null;
  // const token = location.token ? location.state.token : null;

  const handlePasswordChange = (event) => {
    setPassword(event.target.value);
    setError(null); // Clear error when password changes
  };

  const handleConfirmPasswordChange = (event) => {
    setConfirmPassword(event.target.value);
    setError(null); // Clear error when confirm password changes
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (password !== confirmPassword) {
      setError("Passwords do not match!");
    } else if (done === 0) {
      alert("OTP not verified");
    } else {
      try {
        const token=localStorage.getItem('token');
        localStorage.removeItem('token');
        // console.log(token);
        const response = await fetch(`http://localhost:3000/auth/resetpass`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ new_password: password, username: username,token:token }),
        });
        if (response.ok) {
          setPasswordReset(true);
        } else {
          setError("Failed to reset password. Please try again.");
        }
      } catch (error) {
        console.error("Error resetting password:", error);
        setError("An error occurred while resetting the password. Please try again later.");
      }
    }
  };

  return (
    <div className="d-flex justify-content-center align-items-center vh-100">
      <div className="card p-5 shadow-sm" style={{ width: 500 }}>
        <h2 className="mb-4 text-center">Change Password</h2>
        {passwordReset ? (
          <div className="text-center">
            <p className="text-success">Password successfully reset!</p>
            <Link to="/" className="btn btn-primary">Go to Login</Link>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label htmlFor="password">New Password</label>
              <input
                type="password"
                name="password"
                id="password"
                value={password}
                onChange={handlePasswordChange}
                placeholder="Enter your new password"
                className="form-control"
                required
              />
            </div>
            <div className="form-group">
              <label htmlFor="confirm-password">Confirm Password</label>
              <input
                type="password"
                name="confirm-password"
                id="confirm-password"
                value={confirmPassword}
                onChange={handleConfirmPasswordChange}
                placeholder="Confirm your new password"
                className={`form-control ${error ? 'is-invalid' : ''}`}
                required
              />
              {error && <div className="invalid-feedback">{error}</div>}
            </div>
            <div className="form-check mb-4">
              <input
                id="newsletter"
                type="checkbox"
                className="form-check-input"
                required
              />
              <label htmlFor="newsletter" className="form-check-label">
                I accept the{" "}
                <a href="#" className="text-primary">
                  Terms and Conditions
                </a>
              </label>
            </div>
            <button
              type="submit"
              className="btn btn-primary w-100"
            >
              Reset Password
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
