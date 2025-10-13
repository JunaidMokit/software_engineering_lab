import React, { useState } from 'react';
import { Paper, TextInput, Button, Loader } from '@mantine/core';
import { showNotification } from '@mantine/notifications';
import axios from 'axios';

const PassChanger = () => {
  const [formData, setFormData] = useState({
    userName: '',
    oldPass: '',
    newPassFirst: '',
    newPassSecond: '',
  });
  const [loading, setLoading] = useState(false);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      const response = await axios.post(`http://localhost:3000/auth/change-password/`, formData);
      showNotification({
        title: 'Success',
        message: response.data.message,
        color: 'green',
      });
      setFormData({
        userName: '',
        oldPass: '',
        newPassFirst: '',
        newPassSecond: '',
      });
    } catch (error: any) {
      showNotification({
        title: 'Error',
        message: error.response?.data?.error || 'An error occurred',
        color: 'red',
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ textAlign: 'center' }}>
      <h3>Change Password</h3>
      <Paper shadow="md" p="md" style={{ margin: 'auto', maxWidth: 400 }}>
        <form onSubmit={handleSubmit}>
          <TextInput
            name="userName"
            value={formData.userName}
            onChange={handleChange}
            placeholder="Enter username"
            label="Username"
            required
            mb="md"
            autoComplete="new-login"
          />
          <TextInput
            name="oldPass"
            value={formData.oldPass}
            onChange={handleChange}
            placeholder="Enter old password"
            label="Old Password"
            type="password"
            required
            mb="md"
            autoComplete="current-password"
          />
          <TextInput
            name="newPassFirst"
            value={formData.newPassFirst}
            onChange={handleChange}
            placeholder="Enter new password"
            label="New Password"
            type="password"
            required
            mb="md"
            autoComplete="new-password"
          />
          <TextInput
            name="newPassSecond"
            value={formData.newPassSecond}
            onChange={handleChange}
            placeholder="Confirm new password"
            label="Confirm Password"
            type="password"
            required
            mb="md"
            autoComplete="new-password"
          />
          <Button type="submit" fullWidth disabled={loading} mt="md">
            {loading ? <Loader size="sm" color="white" /> : 'Submit'}
          </Button>
        </form>
      </Paper>
    </div>
  );
};

export default PassChanger;
