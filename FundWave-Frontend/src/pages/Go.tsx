import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const RedirectToUser = () => {
  const navigate = useNavigate();
    const username = localStorage.getItem('username');
  useEffect(() => {
    // Redirect to /:username
    if (username) {
      navigate(`/chat/${username}`);
    } else {
      // Handle the case where username is not available
      navigate('/'); // Or redirect to a default page
    }
  }, [username, navigate]);

  return null; // Render nothing
};

export default RedirectToUser;
