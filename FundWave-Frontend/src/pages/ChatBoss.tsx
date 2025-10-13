import React, { useEffect, useState } from 'react';
import { Container, Grid, Col, Card, Text, Avatar, TextInput, Button, Group, Box, ScrollArea } from '@mantine/core';
import axios from 'axios';
import io from 'socket.io-client';

const useSocket = (url: string) => {

  const [socket, setSocket] = useState(null);



  useEffect(() => {

    const socketInstance = io(url);

    setSocket(socketInstance);



    return () => {

      socketInstance.disconnect();

    };

  }, [url]);



  return socket;

};

const ChatGo = () => {
    const username=localStorage.getItem('username');
    const fnd=localStorage.getItem('fnd');
    const [selectedUser, setSelectedUser] = useState(fnd);
  const [users, setUsers] = useState([]);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [selectedImage, setSelectedImage] = useState(null);
  const socket = useSocket('http://localhost:5000'); // Replace with your socket server URL

  const fetchUsers = async () => {
    const response = await axios.get('http://localhost:5000/api/users');
    setUsers(response.data);
  };

  const fetchMessages = async () => {
    const response = await axios.get(`http://localhost:5000/api/messages`, {
      params: { id1: username, id2: selectedUser }, // Replace selectedUser with your target user
    });
    setMessages(response.data);
  };

  const sendMessage = () => {
    if (selectedImage) {
      const formData = new FormData();
      formData.append('image', selectedImage);
      socket.emit('chat message', { text: newMessage, image: formData });
    } else if (newMessage.trim() !== '') {
      socket.emit('chat message', { text: newMessage });
    }
    setNewMessage('');
    setSelectedImage(null);
  };

  useEffect(() => {
    fetchUsers();
    if (socket) {
      socket.on('chat message', (message) => {
        setMessages((prev) => [...prev, message]);
      });
    }
    return () => {
      socket.off('chat message');
    };
  }, [socket]);

  return (
    <Container>
      <Grid>
        <Col span={3}>
          <Card shadow="sm">
            <Text weight={500} mb="md">Users</Text>
            <ScrollArea style={{ height: '400px' }}>
              {users.map((user) => (
                <Group key={user.id} align="center" style={{ cursor: 'pointer' }}>
                  <Avatar src={user.avatar} alt={user.name} />
                  <Text>{user.name}</Text>
                </Group>
              ))}
            </ScrollArea>
          </Card>
        </Col>

        <Col span={9}>
          <Card shadow="sm">
            <Text weight={500} mb="md">Chat</Text>
            <ScrollArea style={{ height: '400px' }}>
              {messages.map((message, index) => (
                <Box key={index} mb="md" style={{ textAlign: message.isMine ? 'right' : 'left' }}>
                  <Text>
                    <strong>{message.sender}</strong>: {message.text}
                  </Text>
                  {message.image && <img src={message.image} alt="Sent" style={{ maxWidth: '100px', borderRadius: '5px' }} />}
                </Box>
              ))}
            </ScrollArea>

            <TextInput
              placeholder="Type a message"
              value={newMessage}
              onChange={(e) => setNewMessage(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
              mb="md"
            />
            <input type="file" onChange={(e) => setSelectedImage(e.target.files[0])} />
            <Group position="apart" mt="md">
              <Button onClick={sendMessage}>Send</Button>
            </Group>
          </Card>
        </Col>
      </Grid>
    </Container>
  );
};

export default ChatGo;
