import {
    TextInput,
    PasswordInput,
    Checkbox,
    Anchor,
    Paper,
    Title,
    Text,
    Container,
    Group,
    Button
} from '@mantine/core';
import {Helmet} from "react-helmet";
//import {IconBrandFacebook, IconBrandGoogle} from "@tabler/icons-react";
import {useState} from 'react';
import { Link, useNavigate } from 'react-router-dom';
const LoginPage = () => {
    // const [email, setEmail] = useState('');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    // const [rememberMe, setRememberMe] = useState(false);
    const navigate = useNavigate();

    const handleSubmit = async (event) => {
       event.preventDefault();

        const response = await fetch('http://localhost:3000/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
               username,
                password
                }),
        });

        let data;
        try {
            data = await response.json();  // Attempt to parse JSON
        } catch (error) {
            data = response;  // Fallback to plain text
        }
        console.log(data);
        console.log(data);
        if (response.ok) {
            localStorage.removeItem('authToken');
            localStorage.removeItem('username');
            if (data.token) {
                    localStorage.setItem('authToken', data.token);
                }
            localStorage.setItem('username', username);
            console.log('Signup successful:', data);
            navigate('/'); 
            
        } else {
            // Handle signup error
            console.error('Login failed:', data);
            alert(`Login failed, try again with Correct Information`);

        }
    };
    
    return (
        <>
            <Helmet>
                <title>Login</title>
            </Helmet>
            <Container size={420} my={40}>
                <Title
                    align="center"
                    sx={() => ({ fontWeight: 900 })}
                >
                    Welcome back to FundWave!
                </Title>
                <Text color="dimmed" size="sm" align="center" mt={5}>
                    Do not have an account yet?{' '}
                    <Anchor size="sm"  component="button">
                    <Link to="/signup">Create account</Link>
                    </Anchor>
                </Text>

                <Paper withBorder shadow="md" p={30} mt={30} radius="md" component="form" onSubmit={handleSubmit}>
                    
                    {/* <TextInput label="Email" placeholder="Your email" required mt="md" value={email} onChange={(e) => setEmail(e.target.value)} /> */}
                    <TextInput label="Username" placeholder="Your Username" required mt="md" value={username} onChange={(e) => setUsername(e.target.value)} />
                    <PasswordInput label="Password" placeholder="Your password" required mt="md" value={password} onChange={(e) => setPassword(e.target.value)} />
                    <Group position="apart" mt="lg">
                        {/* <Checkbox label="Remember me" checked={rememberMe} onChange={(e) => setRememberMe(e.currentTarget.checked)} /> */}
                        <Link to='/forgot/recovered'>
                        <Anchor component="button" size="sm">
                            Forgot password?
                        </Anchor> 
                        </Link>
                    </Group>
                    <Button type="submit" fullWidth mt="xl">
                        Sign in
                    </Button>
                </Paper>
            </Container>
        </>
    );
}

export default LoginPage;
