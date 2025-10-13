import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

// Make sure you define or import `api.url`
// Example: import { api } from './config'; 

export default function Reset() {
  const navigate = useNavigate();
  const [inputValue, setInputValue] = useState("");
  const [error, setError] = useState(null);
  const handleInputChange = (event) => {
    setInputValue(event.target.value);
    setError(null); // Reset error when input changes
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    try {
      const endpoint = `http://localhost:3000/auth/otp`; // Ensure api.url is defined
      const response = await axios.post(endpoint, { username: inputValue });
      if (response.status === 200) {
        console.log(response.data.code);
        // Redirect to OTP page with user, code, and username
        navigate('/forgot/otp', { 
          state: { 
            user: inputValue, 
            code: response.data.code, 
            username: response.data.username 
          }
        });
      }
    } catch (error) {
      console.error("Error:", error);
      // Add null checks to avoid issues
      setError(error?.response?.data?.message || "An unexpected error occurred. Please try again.");
    }
  };

  return (
    <div className="d-flex justify-content-center align-items-center vh-100">
      <div className="card p-5 shadow-sm" style={{ width: 400 }}>
        <h2 className="mb-4 text-center">Reset Password</h2>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="inputValue">Enter Username</label>
            <input
              type="text"
              name="inputValue"
              id="inputValue"
              value={inputValue}
              onChange={handleInputChange}
              placeholder="Enter your username"
              className={`form-control ${error ? 'is-invalid' : ''}`} 
              required
            />
            {error && <div className="invalid-feedback">{error}</div>}
          </div>
          <button type="submit" className="mt-2 btn btn-primary w-100">
            Submit
          </button>
        </form>
      </div>
    </div>
  );
}
