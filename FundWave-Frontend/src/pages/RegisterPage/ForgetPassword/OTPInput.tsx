import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
const EmailVerificationForm = () => {
  const [timerCount, setTimerCount] = useState(30);
  const [disable, setDisable] = useState(false);
  const [OTPinput, setOTPinput] = useState(['', '', '', '']);
  const location = useLocation();
  const code = location.state ? location.state.code : null;
  const username = location.state ? location.state.username : null;
  const navigate=useNavigate();
  useEffect(() => {
    startTimer();
  }, []);
  const startTimer = () => {
    setDisable(true);
    const interval = setInterval(() => {
      setTimerCount(prevCount => {
        if (prevCount <= 0) {
          clearInterval(interval);
          setDisable(false); // Enable the resend link
          return 30; // Reset timer count globally
        }
        return prevCount - 1;
      });
    }, 1000);
    return () => clearInterval(interval);

  };
  const [error, setError] = useState(null);

  const verifyOTP = async () => {
    const otpValue = OTPinput.join(''); // Combine the OTP input
  
    try {
      // Make a POST request to the OTP verification API
      const response = await fetch(`http://localhost:3000/auth/verify-otp`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ otp: otpValue, username: username }), // Send OTP and username
      });
  
      // Check if the response is not successful
      if (!response.ok) {
        throw new Error("Network response was not ok");
            }
         const data = await response.json();
      if (data.token) {
        // OTP verified successfully, navigate to the reset page with state
        localStorage.setItem('token',data.token);
        navigate('/forgot/reset', { state: {token:data.token,done: 1, username: username } });
      } else {
        // Handle the case where OTP is incorrect
        alert("OTP does not match. Please try again.");
      }
    } catch (error) {
      // Handle any errors that occur during the fetch request
      console.error("Error verifying OTP:", error);
      setError("An error occurred while verifying the OTP. Please try again later.");
    }
  };
  

  const resendOTP = () => {
    // Reset timer count globally
    setTimerCount(30);
    startTimer(); // Restart timer on resend
    // Add your resend logic here
    console.log('Resending OTP');
  };

  const handleInputChange = (index, value) => {
    const newInput = [...OTPinput];
    newInput[index] = value;
    setOTPinput(newInput);
    const nextInputIndex = index + 1;
    if (nextInputIndex < OTPinput.length) {
      document.getElementById(`otpInput${nextInputIndex}`).focus();
    }
  };

  return (
    <div className="d-flex justify-content-center align-items-center w-100 vh-100 bg-gray-50">
      <div className="bg-white px-4 py-5 shadow-sm rounded-lg mx-auto w-100 max-w-lg">
        <div className="mx-auto d-flex flex-column w-100 max-w-md">
          <div className="d-flex flex-column align-items-center justify-content-center text-center mb-4">
            <h1 className="font-weight-bold mb-3">Email Verification</h1>
            <p>We have sent a code to your email <span id="email"></span></p>
          </div>

          <form>
            <div className="d-flex flex-column align-items-center">
              <div className="d-flex justify-content-between" style={{ width: '260px' }}>
                {/* Replace input styling with Bootstrap */}
                {Array.from({ length: 4 }, (_, index) => (
                  <input
                    key={index}
                    maxLength="1"
                    id={`otpInput${index}`}
                    className="form-control otp-input mx-1 text-center"
                    type="text"
                    name={`otpInput${index}`}
                    value={OTPinput[index]}
                    onChange={(e) => handleInputChange(index, e.target.value)}
                  />
                ))}
              </div>
              {error && <div className="text-danger text-center mt-2">{error}</div>}

              <div className="mt-4">
                <button type="button" onClick={() => verifyOTP('/another-page')} className="btn btn-primary">Verify Account</button>
              </div>

              <div className="d-flex justify-content-center align-items-center mt-3 text-sm text-gray-500">
                {/* <p className="mb-0">Didn't receive code? </p>
                <a href="#" onClick={resendOTP} className="ml-1" id="resendLink">
                  {disable ? `Resend OTP in ${timerCount}s` : "Resend OTP"}
                </a> */}
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default EmailVerificationForm;
