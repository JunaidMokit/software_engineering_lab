import {
    Badge,
    Card,
    createStyles,
    Flex,
    getStylesRef,
    Group,
    Image,
    PaperProps,
    Progress,
    Stack,
    Text,
} from '@mantine/core';
import { ILoans } from "../types";
import { Link } from "react-router-dom";
import { useEffect, useState } from 'react';

const useStyles = createStyles((theme) => ({
    card: {
        position: 'relative',
        padding: theme.spacing.lg,
        backdropFilter: `blur(16px) saturate(180%)`,
        backgroundColor: theme.colorScheme === 'dark' ? theme.colors.dark[7] : `rgba(255, 255, 255, 0.75)`,
        border: `2px solid rgba(209, 213, 219, 0.3)`,

        [`&:hover .${getStylesRef('image')}`]: {
            transform: 'scale(1.03)',
        },

        '&:hover': {
            boxShadow: theme.shadows.xl,
            border: `2px solid ${theme.colors.primary[7]}`,
            backgroundColor: theme.colors.primary[0],
            transition: 'all 150ms ease',
        }
    },

    title: {
        marginTop: theme.spacing.md,
    },

    image: {
        ref: getStylesRef('image'),
        transition: 'transform 150ms ease',
    }
}));

interface IProps extends PaperProps {
    data: ILoans;
    showActions?: boolean;
}

const LoanCard = ({ data, showActions }: IProps) => {
    const { classes } = useStyles();
    const {
        mainImage,
        username,
        _id,
        title,
        createdAt,
        targetAmount, 
        deadlineDate,
        category,
        interest,
        story,
        condition
    } = data;
    
    const linkProps = { to: `/loans/${_id}`, rel: 'noopener noreferrer' };

    // Calculate days left for progress (assumes deadlineDate is in ISO format)
    const deadline = new Date(deadlineDate);
    const today = new Date();
    const daysLeft = Math.max(Math.ceil((deadline.getTime() - today.getTime()) / (1000 * 60 * 60 * 24)), 0);
    const [People, setPeople] = useState(0);
    const findPeople = async () => {
        try {
            const response = await fetch(`http://localhost:3000/api/bids/${_id}`);
            const data = await response.json();
            if(data.noBids){
                setPeople(0);
                return;
            }
            setPeople(data.data.length);
        } catch (error) {
            console.error('Error fetching user data:', error);
        }
    }
    useEffect(() => {
        findPeople();
    }
    , [_id]);
    const [user, setUser] = useState('');

    const findUser = async () => {
        try {
            const response = await fetch(`http://localhost:3000/auth/user/${username}`);
            const data = await response.json();
            console.log(data);
            setUser(data);
        } catch (error) {
            console.error('Error fetching user data:', error);
        }
    }

    useEffect(() => {
        findUser();
    }, [username]);
    return (
        <Card radius="sm" shadow="md" ml="xs" component={Link} {...linkProps} className={classes.card}>
            <Card.Section>
                <Image src={`http://localhost:3000/api/campaign${user.img}`} height={280} className={classes.image} />
            </Card.Section>

            <Card.Section pt={0} px="md" pb="md">
                <Stack>
                    <Text className={classes.title} lineClamp={1} fw={500} size="lg">
                        {title}
                    </Text>

                    <Group position="apart">
                        <Text size="xs" transform="uppercase" color="dimmed" fw={700}>{username}</Text>
                        <Badge variant="dot" color="secondary">{category}</Badge>
                    </Group>

                    {/* {showActions && <Text lineClamp={3} size="sm">{story}</Text>} */}
                    <Text lineClamp={3} size="sm"><b>Target Amount: </b>{targetAmount}</Text>
                    <Progress value={100 - (daysLeft / 30) * 100} />

                    <Flex justify="space-between">
                        <Text><b>{People}</b> Interested</Text>
                        <Text>Currntly <b>{condition}</b></Text>
                    </Flex>

                    {/*{showActions && <Button>Donate Now</Button>}*/}
                </Stack>
            </Card.Section>
        </Card>
    );
};

export default LoanCard;
