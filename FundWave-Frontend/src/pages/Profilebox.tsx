import React, { useEffect, useState } from 'react';
import {
  Box,
  Button,
  Card,
  Container,
  Flex,
  Text,
  Title,
  Stack,
  Paper,
  SimpleGrid,
  Group,
  Select,
  Divider,
  Image
} from "@mantine/core";
import { useParams } from 'react-router-dom';
import { Helmet } from 'react-helmet';
import { CampaignsTable, DonatorsTable, FileDropzone } from '../components';
import axios from 'axios';
import api from '../util/api';

const Profilebox = () => {
  const username = localStorage.getItem('username');
  const { id } = useParams();  // id could be used for other dynamic routing or page info
  const [sortOrder, setSortOrder] = useState("Loans");
  const [userInfo, setUserInfo] = useState({ bkash: '', nagad: '', rocket: '' });

  // Fetch user info on component mount
    const fetchUserInfo = async () => {
      try {
        const response = await fetch(`http://localhost:3000/auth/user/${id}`);
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        const data = await response.json();
        setUserInfo(data);  // Assuming the data returned includes bkash, nagad, and rocket fields
      } catch (error) {
        console.error('Error fetching user data:', error);
      }
    };
    useEffect (() => {
      fetchUserInfo();
    }
    , [id]);
  // Function to update user info via API
  const handleUpdate = async (type) => {
    const newValue = prompt(`Enter new ${type} number:`);
    if (newValue) {
      try {
        const updatedInfo = { ...userInfo, [type.toLowerCase()]: newValue };

        // Send a PUT request to update user data
        const response = await fetch(`http://localhost:3000/auth/user/${username}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(updatedInfo),
        });

        if (!response.ok) {
          throw new Error('Failed to update user data');
        }

        // Update local state with new value
        setUserInfo(updatedInfo);

        alert(`${type} number updated successfully!`);
      } catch (error) {
        console.error('Error updating user data:', error);
        alert('Failed to update user data.');
      }
    }

  };
  const [image, setImage] = useState('https://via.placeholder.com/150'); // Default placeholder image
  const handleImageUpload1 = async (event) => {
    const file = event.target.files[0]; // Get the selected file
    if (file) {
      // const imageURL = URL.createObjectURL(file); 
      setImage(file);
      console.log(file);
      alert("done iamge");
  }
}

const handleImageUpload = async (event) => {
  const file = event.target.files[0]; // Get the selected file
  if (file) {
    console.log(file);
    try {
      const formData = new FormData();
      formData.append('image', file);
      console.log(formData);

    // Send a PUT request to update user data
    const response = await fetch(`http://localhost:3000/auth/img/${username}`, {
      method: 'PUT',
      body: formData,
    });
      console.log(response);

      if (!response.ok) {
        throw new Error('Failed to update user data');
      }

      const updatedUserInfo = await response.json(); // Assuming the server responds with updated user data
      setUserInfo(updatedUserInfo); // Update the user info state with the response data
      fetchUserInfo(); // Refetch user info to update the UI
      alert('Image uploaded successfully!');
    } catch (error) {
      console.error('Error uploading image:', error);
      alert('Failed to upload image');
    }
}
};

const handleImageUpload10 = async (event) => {
  const file = event.target.files[0];
  if (file) {
    const imageURL = URL.createObjectURL(file);
    setImage(imageURL);

    const formData = new FormData();
    formData.append('image', file);

    try {
      const response = await fetch(`http://localhost:3000/auth/img/${username}`, {
        method: 'PUT',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Error: ${response.status}`);
      }

      const updatedUserInfo = await response.json();
      setUserInfo(updatedUserInfo);
      alert('Image uploaded successfully!');
    } catch (error) {
      console.error('Failed to update user data:', error);
      alert('Failed to upload image');
    }
  }
};



  
  return (
    <>
      <Helmet>
        <title>Dashboard</title>
      </Helmet>
      <Box>
        <Container fluid my="xl">
          <Stack spacing="xl">
            <Title order={3}>Good evening, {username}</Title>
            <Paper shadow="xs" p="lg" radius="md" withBorder>
          <Title order={4}>Personal Details</Title>
          <Divider my="sm" />
          <Flex align="center" justify="space-between" gap="md">
            <Flex direction="column" gap="xs">
              <Text size="lg"><strong>Name:</strong> {userInfo.name || 'Not Available'}</Text>
              <Text size="lg"><strong>Username:</strong> {userInfo.username || 'Not Available'}</Text>
              <Text size="lg"><strong>Email:</strong> {userInfo.email || 'Not Available'}</Text>
              <Text size="lg"><strong>ID:</strong> {userInfo.id || 'Not Available'}</Text>
            </Flex>
            <Flex direction="column" gap="xs">
            <Image src={`${api.img}${userInfo.img}` || 'https://via.placeholder.com/150'} width={150} height={150} radius="lg" />

            {username == id && (
            <input 
                type="file" 
                accept="image/*" 
                onChange={handleImageUpload} 
              />
            )}
            </Flex>
          </Flex>
        </Paper>

                    <Card shadow="xs" padding="md">
              <Flex align="center" justify="space-between" gap="md">
                <Flex align="center" gap="xs">
                  <Title order={3}>Bkash:</Title>
                  <Text size="lg">{userInfo.bkash || '017XXXXXXXX'}</Text>
                  <Button onClick={() => handleUpdate("Bkash")} variant="light">Edit</Button>
                </Flex>

                <Flex align="center" gap="xs">
                  <Title order={3}>Nagad:</Title>
                  <Text size="lg">{userInfo.nagad || '017XXXXXXXX'}</Text>
                  <Button onClick={() => handleUpdate("Nagad")} variant="light">Edit</Button>
                </Flex>

                <Flex align="center" gap="xs">
                  <Title order={3}>Rocket:</Title>
                  <Text size="lg">{userInfo.rocket || '017XXXXXXXX'}</Text>
                  <Button onClick={() => handleUpdate("Rocket")} variant="light">Edit</Button>
                </Flex>
              </Flex>
            </Card>
            {/* Example Stats Section */}
            <SimpleGrid cols={4} breakpoints={[
              { maxWidth: 'md', cols: 2, spacing: 'md' },
              { maxWidth: 'sm', cols: 1, spacing: 'sm' }
            ]}>
              <Paper p="md">
                <Group position="apart">
                  <Text>Total Donations</Text>
                  {/* Other content */}
                </Group>
              </Paper>

              <Paper p="md">
                <Group position="apart">
                  <Text>Today's Donations</Text>
                  {/* Other content */}
                </Group>
              </Paper>

              <Paper p="md">
                <Group position="apart">
                  <Text>Average Donations per Campaign</Text>
                  {/* Other content */}
                </Group>
              </Paper>

              <Paper p="md">
                <Group position="apart">
                  <Text>Active Campaigns</Text>
                  {/* Other content */}
                </Group>
              </Paper>
            </SimpleGrid>

            <Paper p="md">
              <Card.Section mb="lg">
                <Flex align="center" justify="space-between">
                  <Box>
                    <Title size={18} mb="sm">Activities</Title>
                    <Text size="sm">Details of {id}'s Activities</Text>
                  </Box>
                  <Select
                    label=""
                    placeholder="Sort by"
                    value={sortOrder}
                    onChange={setSortOrder}
                    data={[
                      { value: "Loans", label: "Loans" },
                      { value: "Campaign", label: "Campaign" },
                      { value: "Bids", label: "ALL Bids" },
                      { value: "Final", label: "Final Bids" },]}
                  />
                </Flex>
              </Card.Section>
              <Card.Section>
                {sortOrder === "Campaign" && <CampaignsTable id={id} />}
                {sortOrder === "Loans" && <DonatorsTable id={id} type={sortOrder}/>}
                {sortOrder === "Bids" && <DonatorsTable id={id} type={sortOrder} />}
                {sortOrder === "Final" && <DonatorsTable id={id} type={sortOrder} />}
              </Card.Section>
            </Paper>
          </Stack>
        </Container>
      </Box>
    </>
  );
};

export default Profilebox;
