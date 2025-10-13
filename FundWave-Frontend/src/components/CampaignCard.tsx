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
import {ICampaign} from "../types";
import {Link} from "react-router-dom";
import {useEffect, useState} from 'react';
import api from '../util/api';

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
    data: ICampaign;
    showActions?: boolean;
}
const CampaignCard = ({data, showActions}: IProps) => {
    const {classes} = useStyles();
    const {
        mainImage,
        _id,
        title,
        amountRaised,
        daysLeft,
        contributors,
        story,
        category,
        username,
        deadlineDate,
        Amount,
        createdAt,
        target,
        imageUrl
    } = data;

    const [campaign, setCampaign] = useState<ICampaign | null>(null);
    const [donations, setDonations] = useState<any[]>([]);
    const [updatedAmountRaised, setUpdatedAmountRaised] = useState<number>(0);
    const img=api.img;
    useEffect(() => {
        const fetchCampaignData = async () => {
            if (_id) {
                try {
                    const campaignResponse = await fetch(`http://localhost:3000/api/campaign/${_id}`);
                    const donationResponse = await fetch(`http://localhost:3000/api/fundpayments/${_id}`);

                    if (!campaignResponse.ok || !donationResponse.ok) {
                        throw new Error("Network response was not ok");
                    }
                    const campaignData = await campaignResponse.json();
                    const donationData = await donationResponse.json();
                    const tip = donationData.map(d => d.tip).reduce((a, b) => a + b, 0);
                    const total = donationData.map(d => d.Amount).reduce((a, b) => a + b, 0);
                    const totalAmountRaised=total-tip;
                    setUpdatedAmountRaised(totalAmountRaised);
                    setCampaign(campaignData);
                    setDonations(donationData);
                } catch (error) {
                    console.error("Error fetching campaign or donation data:", error);
                }
            }
        };

        fetchCampaignData();
    }, [_id]);
    
    const linkProps = {to: `/campaigns/${_id}`, rel: 'noopener noreferrer'};

    return (
        <Card radius="sm" shadow="md" ml="xs" component={Link} {...linkProps} className={classes.card}>
            <Card.Section>
                <Image src={`${img}${imageUrl}`} height={280} className={classes.image}/>
            </Card.Section>

            <Card.Section pt={0} px="md" pb="md">
                <Stack>
                    <Text className={classes.title} lineClamp={1} fw={500} size="lg">
                        {title}
                    </Text>

                    <Group position="apart">
                        <Text size="xs"> By <b>{username}</b></Text>
                        <Badge variant="dot" color="secondary">{category}</Badge>
                    </Group>
                    <Text lineClamp={3} size="sm">
                        <b>Deadline: </b>
                        {target === "deadline"
                            ? `${new Date(deadlineDate).getUTCDate()} ${new Date(deadlineDate).toLocaleString('en-US', { month: 'long' })} ${new Date(deadlineDate).getUTCFullYear()}`
                            : "No Deadline"}
                    </Text>
                     {Amount &&
                    <Progress value={(updatedAmountRaised / Amount) * 100} />
                     }
                     {!Amount &&
                    <Progress value={100} />
                     }


                    <Flex justify="space-between">
                        <Text><b>৳{updatedAmountRaised}</b> raised</Text>
                        <Text><b>{donations.length}</b> donations</Text>
                    </Flex>

                </Stack>
            </Card.Section>
        </Card>
    );
};

export default CampaignCard;
