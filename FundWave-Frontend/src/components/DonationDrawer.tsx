import { useState } from 'react';
import {
    ActionIcon,
    Anchor,
    Button,
    Checkbox,
    Container,
    Drawer,
    DrawerProps,
    Flex,
    Group,
    Image,
    NumberInput,
    Paper,
    PaperProps,
    Popover,
    Radio,
    ScrollArea,
    Slider,
    Stack,
    Text,
    TextInput,
    ThemeIcon,
    Transition,
    useMantineTheme
} from "@mantine/core";
import {
    IconBrandApple,
    IconBrandGoogle,
    IconCreditCard,
    IconCurrencyTaka,
    IconInfoCircleFilled,
    IconShieldCheckFilled
} from "@tabler/icons-react";
import axios from 'axios'; // Ensure you have axios imported
import { CountrySelect } from "./index";
import { ICampaign } from "../types";

interface IProps extends Pick<DrawerProps, 'opened' | 'onClose' | 'size'> {
    campaign?: ICampaign;
    iconSize: number;
}

const DonationDrawer = ({ campaign, iconSize, ...others }: IProps) => {
    const username = localStorage.getItem('username');
    const [payment, setPayment] = useState('');
    const [donationAmount, setDonationAmount] = useState<number>(0);
    const [tipPercentage, setTipPercentage] = useState<number>(2); // Start with 2% as default
    const [isAnonymous, setIsAnonymous] = useState<boolean>(false); // Correct handling of checkbox state
    const [error, setError] = useState<string | null>(null); // State for error handling
    const [loading, setLoading] = useState<boolean>(false); // State for loading handling
    const theme = useMantineTheme();

    const paperProps: PaperProps = {
        p: "md",
        withBorder: true,
        sx: { backgroundColor: theme.white }
    };

    // Calculate tip and total donation amount
    const tipAmount = (donationAmount * tipPercentage) / 100;
    const totalAmount = donationAmount + tipAmount;

    const handlePayment = async () => {
        console.log("tipAmount", tipAmount);
        // Clear error state
        setError(null);

        // Validate the total amount
        if (totalAmount <= 0) {
            setError('Please enter a valid donation amount.');
            return;
        }

        setLoading(true);

        try {
            // Making the POST request with Axios
            const { data } = await axios.post('http://localhost:3000/api/payment/givepay', {
                tip:tipAmount,
                plan: "Campaign",
                price: totalAmount,
                username: username,
                id: campaign?._id,
            });

            // Check if the URL is present in the response
            if (data.url) {
                // Redirect the user to the payment page
                window.location.replace(data.url);
            } else {
                setError('Payment failed. Please try again.');
            }
        } catch (error) {
            console.error('Error:', error);
            setError('An error occurred while processing your request.');
        } finally {
            // Ensure loading state is handled in both success and error cases
            setLoading(false);
        }
    };

    return (
        <Drawer
            position="bottom"
            title="Make a Donation"
            size="100%"
            scrollAreaComponent={ScrollArea.Autosize}
            {...others}
        >
            <Container>
                <Stack>
                    <Flex gap="xs" align="center">
                        <Image src={campaign?.mainImage} height={96} width={120} fit="contain" radius="sm" />
                        <Text>You&apos;re supporting <b>{campaign?.title}</b></Text>
                    </Flex>
                    <NumberInput
                        size="md"
                        label="Enter your donation"
                        precision={2}
                        rightSection={<IconCurrencyTaka size={iconSize} />}
                        value={donationAmount}
                        onChange={(value) => setDonationAmount(value || 0)} // Set donation amount
                    />
                    <Paper {...paperProps}>
                        <Text fw={500}>Tip FundWave services</Text>
                        <Text size="sm" my="xs">Fundwave has a 0% platform fee for organizers. Fundwave will continue offering its services thanks to donors who will leave an optional amount here:</Text>
                        <Slider
                            marks={[
                                { value: 2, label: '2%' },
                                { value: 5, label: '5%' },
                                { value: 8, label: '8%' },
                            ]}
                            mb="lg"
                            value={tipPercentage}
                            onChange={setTipPercentage} // Update tip percentage
                        />
                    </Paper>
                    <Paper {...paperProps}>
                        <Stack>
                            <Group spacing={4}>
                                {/* <Checkbox
                                    checked={isAnonymous} // Correct usage of `checked`
                                    onChange={(event) => setIsAnonymous(event.currentTarget.checked)}
                                    label="Don't display my name publicly on the fundraiser."
                                /> */}
                                <Popover width={200} position="bottom" withArrow shadow="md">
                                    <Popover.Target>
                                        <ActionIcon color="primary" variant="subtle">
                                            <IconInfoCircleFilled size={iconSize} />
                                        </ActionIcon>
                                    </Popover.Target>
                                    {/* <Popover.Dropdown>
                                        <Text size="sm">Your name will only be visible to the organizer, any team members, and the beneficiary</Text>
                                    </Popover.Dropdown> */}
                                </Popover>
                            </Group>
                        </Stack>
                    </Paper>
                    <Paper {...paperProps}>
                        <Stack>
                            <Text fw={700} size="lg">Your donation</Text>
                            <Group position="apart">
                                <Text>Your donation</Text>
                                <Text fw={500}>${donationAmount.toFixed(2)}</Text>
                            </Group>
                            <Group position="apart">
                                <Text>Fundwave tip</Text>
                                <Text fw={500}>${tipAmount.toFixed(2)}</Text>
                            </Group>
                            <Group position="apart">
                                <Text>Total due today</Text>
                                <Text fw={500}>${totalAmount.toFixed(2)}</Text>
                            </Group>
                            <Button size="lg" onClick={handlePayment} disabled={loading}>
                                {loading ? 'Processing...' : 'Donate Now'}
                            </Button>
                            {error && <Text color="red">{error}</Text>}
                        </Stack>
                    </Paper>
                    <Paper {...paperProps}>
                        <Stack>
                            <Text size="sm">By continuing, you agree with <Anchor>FundWave terms</Anchor> and <Anchor>privacy notice.</Anchor></Text>
                            <Text size="sm">Learn more about <Anchor>pricing and fees.</Anchor></Text>
                            <Flex gap="sm">
                                <ThemeIcon size="lg" variant="light" color="blue">
                                    <IconShieldCheckFilled size={18} />
                                </ThemeIcon>
                                <Text size="sm">We guarantee you a full refund for up to a year in the rare case that fraud occurs.&nbsp;<Anchor>See our FundWave Giving Guarantee.</Anchor></Text>
                            </Flex>
                        </Stack>
                    </Paper>
                </Stack>
            </Container>
        </Drawer>
    );
};

export default DonationDrawer;
