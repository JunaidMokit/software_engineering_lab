import { useEffect, useState } from 'react';
import { Avatar, Button, Flex, Paper, Stack, Text } from '@mantine/core';
import { IconSend } from '@tabler/icons-react';
import { Link } from 'react-router-dom';

interface IProps {
    username: string;
}

const UserCard = ({ username, ...others }: IProps) => {
    const [userInfo, setUserInfo]= useState<any>(null);

    useEffect(() => {
        const fetchUserInfo = async () => {
            try {
                const response = await fetch(`http://localhost:3000/auth/user/${username}`);
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                const data = await response.json();
                setUserInfo(data);
            } catch (error) {
                console.error('Error fetching user data:', error);
            }
        };

        fetchUserInfo();
    }, [username]);

    if (!userInfo) {
        return <Text>Loading...</Text>;
    }

    return (
        <Paper {...others}>
            <Flex gap="lg" align="center">
                <Avatar src={`http://localhost:3000/api/campaign${userInfo?.img}`} size={120} radius={120} />
                <Stack spacing="xs" align="flex-start">
                    <Text ta="center" fz="lg" weight={500}>
                        {userInfo.username}
                    </Text>
                    <Text ta="center" c="dimmed" fz="sm">
                        {userInfo.email} • {userInfo.job}
                    </Text>
                    <Button variant="light" leftIcon={<IconSend size={18} />} fullWidth>
                    <Link to={`/chat/${userInfo.username}`}>Send Message</Link>
                    </Button>
                </Stack>
            </Flex>
        </Paper>
    );
};

export default UserCard;
