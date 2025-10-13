import { Link, useParams } from "react-router-dom";
import { useEffect, useState } from "react";
import { DateInput } from "@mantine/dates";
import {
    Accordion,
    ActionIcon,
    Anchor,
    Avatar,
    Box,
    Button,
    Card,
    Container,
    Divider,
    Flex,
    Grid,
    Group,
    Image,
    Modal,
    NumberInput,
    Paper,
    PaperProps,
    Progress,
    Rating,
    Select,
    Space,
    Stack,
    Text,
    TextInput,
    TextProps,
    Title,
    TitleProps,
    UnstyledButton
} from "@mantine/core";
import { IconFlag, IconHeart, IconHeartFilled, IconSeparator, IconShare } from "@tabler/icons-react";
import { useDisclosure, useMediaQuery, useToggle } from "@mantine/hooks";
import { BackButton, NotFound, UserCard } from "../components";
import LenderCard from "../components/LenderCard";
import { Helmet } from "react-helmet";
import * as dayjs from "dayjs";
import * as LocalizedFormat from "dayjs/plugin/localizedFormat";
import { notifications } from "@mantine/notifications";
import loan from "../sections/Home/loan";
// Instead of this:
import Section from "@mantine/core";

import { AppShell } from "@mantine/core"; // or any other relevant layout component
import ReviewModal from "./ReviewModal";

const LoanDetailsPage = (): JSX.Element => {

    dayjs.extend(LocalizedFormat);
    const { id } = useParams();
    const [Loans, setLoans] = useState<any>();
    const [opened, { open, close }] = useDisclosure(false);
    const [donateOpened, { open: donateOpen, close: donateClose }] = useDisclosure(false);
    const [username, setUsername] = useState(localStorage.getItem('username'));
    const [following, setFollowing] = useToggle();
    const matchesMobile = useMediaQuery('(max-width: 768px)');
    // Modal for Bid for Lend
    const [bidModalOpened, { open: openBidModal, close: closeBidModal }] = useDisclosure(false);
    const [bidType, setBidType] = useState<string | null>(null);
    const [maxTime, setMaxTime] = useState<Date | null>(null);
    const [interest, setInterest] = useState<number | "">(0);

    const paperProps: PaperProps = {
        p: "md",
        shadow: "sm",
    };
    const titleProps: TitleProps = {
        size: 32,
        weight: 700,
        transform: 'capitalize',
        sx: { lineHeight: '40px' }
    };

    const subTitleProps: TextProps = {
        size: 20,
        weight: 600,
        sx: { lineHeight: '28px' }
    };

    const iconSize = 18;
    const [reviews, setReviews] = useState<any[]>([]);


    // Fetch reviews when component mounts
    const fetchReviews = async () => {
        try {
            const response = await fetch(`http://localhost:3000/api/loans/review/${id}`);
            if (!response.ok) {
                throw new Error('Failed to fetch reviews');
            }
            const data = await response.json();
            setReviews(data);
        } catch (err) {
            console.log('Error fetching reviews:', err);
        }
    };
    useEffect(() => {
        fetchReviews();
    }, [id]);

    const [targetAmount, setTargetAmount] = useState(0);
    const [deadlineDate, setDeadlineDate] = useState(null);
    const [Emi, setemitype] = useState('');

    const fetchLoanData = async () => {
        if (id) {
            try {
                const response = await fetch(`http://localhost:3000/api/loans/${id}`);
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                const data = await response.json();
                setLoans(data);
                setemitype(data?.donationType);
                setTargetAmount(data?.targetAmount);
                setDeadlineDate(data?.deadlineDate);
                // console.log(data?.donationType);
                // console.log(data?.targetAmount);
                // console.log(data?.deadlineDate);
                // console.log(Emi);
                // console.log(targetAmount);
                // console.log(deadlineDate);
            } catch (error) {
                console.error('Error fetching loan data:', error);
            }
        }
    };
    useEffect(() => {
        fetchLoanData();
    }, [id]);




    const [searchTerm, setSearchTerm] = useState('');

    const handleSearch = (event: React.ChangeEvent<HTMLInputElement>) => {
        setSearchTerm(event.target.value);
    };
    const [final, setFinal] = useState(false);
    const [mefinal, setMefinal] = useState(false);
    const [medone, setMedone] = useState(false);

    const [Lender, setLender] = useState<any[]>([]);
    const [filteredLender, setFilteredLender] = useState<any[]>([]);
    const fetchLenderData = async () => {
        fetch(`http://localhost:3000/api/bids/${id}`)
            .then((response) => response.json())
            .then((data) => setFilteredLender(data.data))
            .catch((error) => console.error('Error fetching user data:', error));
        console.log(filteredLender);
        setFinal(filteredLender?.some(lender => lender.final === true));
        setMefinal(filteredLender?.find(lender => lender.username === username && lender.final === true));
        setMedone(filteredLender?.some(lender => lender.username === username));

    }
    useEffect(() => {
        fetchLenderData();
    }
        , [Loans?._id, username]);


    useEffect(() => {
        if (searchTerm != "") {
            const result = Lender?.filter(lender =>
                lender?.username?.toLowerCase().includes(searchTerm.toLowerCase())
            );
            setFilteredLender(result ? result : null);
        } else {
            setFilteredLender(Lender);
        }
    }, [searchTerm]);

    const handleBidSubmit = async () => {
        if (id && bidType && maxTime && username) {

            try {
                const response = await fetch(`http://localhost:3000/api/bids`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({
                        loanId: id,
                        username,
                        bidType,
                        maxTime,
                        interest
                    }),
                });
                if (!response.ok) {
                    throw new Error("Failed to submit bid");
                }
                notifications.show({
                    title: "Bid submitted",
                    message: "Your bid for lending has been submitted successfully.",
                    withBorder: true,
                    styles: (theme) => ({
                        root: {
                            backgroundColor: theme.colors.green[6],
                            borderColor: theme.colors.green[6],
                            '&::before': { backgroundColor: theme.white },
                        },
                        title: { color: theme.white },
                        description: { color: theme.white },
                        closeButton: {
                            color: theme.white,
                            '&:hover': { backgroundColor: theme.colors.green[7] },
                        },
                    }),
                });
                fetchLenderData();

                closeBidModal();
            } catch (error) {
                console.error("Error submitting bid:", error);
            }
        }
    }
    const [loaner, setLoaner] = useState<any>();
    const fetchuserinfo = async () => {

        try {
            const response = await fetch(`http://localhost:3000/auth/user/${Loans?.username}`);
            if (!response.ok) {
                throw new Error("Network response was not ok");
            }
            const data = await response.json();
            setLoaner(data);
            console.log(data);
        } catch (error) {
            console.error("Error fetching user data:", error);
        }
    }
    useEffect(() => {
        fetchuserinfo();
    }, [Loans?.username]);
    const own = Loans?.username === username;

    const [openedReviewModal, setOpenedReviewModal] = useState(false);

    const handleOpenReviewModal = () => setOpenedReviewModal(true);
    const handleCloseReviewModal = () => setOpenedReviewModal(false);

    const [updatemodal, setupdatemodal] = useState(false);
    const handleupdatemodal = () => setupdatemodal(true);
    const closeupdatemodal = () => setupdatemodal(false);

    const handleReviewSubmit = () => {
        fetchReviews();
    };
    const handleupdate = async () => {
        const payload = {
            targetAmount,
            deadlineDate,
            donationType: Emi,
        };
        try {
            const response = await fetch(`http://localhost:3000/api/loans/${id}`, {
                method: 'put',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload),
            });

            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            const data = await response.json();
            console.log('Success:', data);
            fetchLoanData();
            fetchLenderData();
            closeupdatemodal();
        } catch (error) {
            console.error('Error:', error);
        }
    };
    return (
        <>
            <Helmet>
                <title>{Loans?.title}</title>
            </Helmet>
            <Box>
                {Loans ? (
                    <Container size="lg">
                        <BackButton mb="md" />
                        <Grid>
                            <Grid.Col lg={8}>
                                <Stack>
                                    <Card padding="md" shadow="sm">
                                        <Card.Section>
                                            <Image src={`http://localhost:3000/api/campaign${loaner?.img}`} height={480} />
                                        </Card.Section>
                                        <Stack mt="md">
                                            <Title>{Loans?.title}</Title>

                                            {!matchesMobile ? (
                                                <Flex gap="xs" align="center">
                                                    <Text size="sm">Loan created by</Text>
                                                    <UnstyledButton component={Anchor}>
                                                        <Flex gap="xs" align="center">
                                                            <Avatar src={Loans?.createdByImage} radius="xl" size="sm" />
                                                            <Text size="sm">{Loans?.username}</Text>
                                                        </Flex>
                                                    </UnstyledButton>
                                                    <IconSeparator size={18} />
                                                    <Text component={Anchor} size="sm">{Loans?.country}</Text>
                                                    <IconSeparator size={18} />
                                                    <Text component={Anchor} size="sm">{Loans?.category}</Text>
                                                </Flex>
                                            ) : (
                                                <Stack>
                                                    <Flex gap="md">
                                                        <Text size="sm">This lending requested by</Text>
                                                        <UnstyledButton component={Anchor}>
                                                            <Flex gap="xs" align="center">
                                                                <Image src={`http://localhost:3000/api/campaign${loaner?.img}`} radius="xl" size="sm" />
                                                                <Text size="sm">{Loans?.username}</Text>
                                                            </Flex>
                                                        </UnstyledButton>
                                                    </Flex>

                                                    <Group>
                                                        <Text size="sm">Location - <Anchor>{Loans?.country}</Anchor></Text>
                                                        <Text size="sm">Category - <Anchor>{Loans?.category}</Anchor></Text>
                                                    </Group>
                                                </Stack>
                                            )}
                                            <Text {...subTitleProps}>Why I Need This</Text>
                                            <Text size="sm" dangerouslySetInnerHTML={{ __html: Loans?.story || '' }} />
                                        </Stack>
                                    </Card>
                                    <Paper {...paperProps}>
                                        <Text {...subTitleProps} mb="sm">Lender</Text>
                                        <UserCard username={Loans?.username} />

                                    </Paper>
                                    <Paper {...paperProps}>
                                        <Text>Deadline: {dayjs(Loans?.deadlineDate).format('LL')}</Text>
                                    </Paper>
                                    <Paper {...paperProps}>
                                        <Text>Created on {dayjs(Loans?.createdAt).format('LL')}</Text>
                                    </Paper>
                                    <Paper {...paperProps}>
                                        <Title {...subTitleProps} mb="sm">Review Section{reviews.length}</Title>
                                        {reviews.length > 0 ? (
                                            <Stack spacing="md">
                                                {reviews.map((review) => (
                                                    <Paper padding="md" shadow="xs" key={review.id} withBorder>
                                                        <Flex justify="space-between" align="center">
                                                            <Text size="sm" color="dimmed">
                                                                Reviewed At: {new Date(review.createdAt).toLocaleDateString()}
                                                            </Text>
                                                            <Flex align="center">
                                                                {/* {[...Array(10)].map((_, index) => (
                                                                    <ActionIcon key={index} size={18} color="blue">
                                                                        {index < review.star ? (
                                                                            <IconHeartFilled />
                                                                        ) : (
                                                                            <IconHeart />
                                                                        )}
                                                                    </ActionIcon>
                                                                ))} */}

                                                                <Rating value={review.rating} size="lg" />                                                            </Flex>
                                                        </Flex>
                                                        <Text mt="md">{review.message}</Text>
                                                    </Paper>
                                                ))}
                                            </Stack>
                                        ) : (
                                            <Text>No reviews yet. Be the first to write one!</Text>
                                        )}
                                    </Paper>
                                    {!matchesMobile && mefinal && (
                                        <Button
                                            onClick={handleOpenReviewModal}
                                            variant="outline"
                                            color="secondary"
                                            fullWidth
                                        >Reviews Loans
                                        </Button>

                                    )}
                                </Stack>
                            </Grid.Col>
                            <Grid.Col lg={4}>

                                <Stack>
                                    {!matchesMobile && (
                                        <Paper {...paperProps}>
                                            <Stack spacing="sm">
                                                <Button variant="outline" size="xl">৳{Loans?.targetAmount}</Button>

                                                {Loans?.condition == "Completed" ? (
                                                    <Button variant="outline" disabled={true} size="xl">Completed</Button>

                                                ) : username == Loans?.username && !final ? (
                                                    <Button variant="outline" onClick={handleupdatemodal} size="xl">Update Loans</Button>
                                                ) : username == Loans?.username && final ? (
                                                    <Button variant="outline" disabled size="xl">Update Loans</Button>
                                                ) : medone ? (
                                                    <Button disabled>
                                                        BID Done
                                                    </Button>

                                                ) : !final ? (
                                                    <Button
                                                        size="xl"
                                                        disabled={Lender?.some(lender => lender.username === username)}
                                                        onClick={openBidModal}
                                                    >
                                                        BID for Lend
                                                    </Button>

                                                ) : (
                                                    <Button disabled size="xl">Final</Button>
                                                )}
                                                {/* {final ? (
                                                    <Button size="xl">Transaction Page</Button>
                                                ) : null} */}



                                            </Stack>
                                        </Paper>
                                    )}
                                    {mefinal && final ? (
                                        <Paper {...paperProps}>
                                            <Text {...subTitleProps} mb="sm">Transactions Page</Text>
                                            <Link
                                                to={`/loans/trans/${Loans._id}`}
                                                style={{
                                                    textDecoration: 'none', // Remove underline
                                                    color: 'white',         // Text color
                                                    backgroundColor: 'green', // Background color
                                                    padding: '10px 20px',   // Add some padding
                                                    borderRadius: '5px',     // Round the corners
                                                    display: 'inline-block',  // Make it look like a button
                                                }}
                                            >
                                                View Transactions
                                            </Link>
                                        </Paper>
                                    ) : null}

                                    {own ? (
                                        <Paper {...paperProps}>
                                            <Text {...subTitleProps} mb="sm">Transactions Page</Text>
                                            <Link
                                                to={`/loans/trans/${Loans._id}`}
                                                style={{
                                                    textDecoration: 'none', // Remove underline
                                                    color: 'white',         // Text color
                                                    backgroundColor: 'green', // Background color
                                                    padding: '10px 20px',   // Add some padding
                                                    borderRadius: '5px',     // Round the corners
                                                    display: 'inline-block',  // Make it look like a button
                                                }}
                                            >
                                                View Transactions
                                            </Link>
                                        </Paper>
                                    ) : null}

                                    <Paper {...paperProps}>
                                        <Text {...subTitleProps} mb="md">Interested Lender </Text>
                                        <TextInput
                                            placeholder="Search Lender"
                                            value={searchTerm}
                                            onChange={handleSearch}
                                            mb="md"
                                        />
                                        {filteredLender ? (
                                            filteredLender.map((lender, index) => (
                                                <>
                                                    <Space h="md" />
                                                    <Box
                                                        style={{
                                                            border: '1px solid #ccc',
                                                            padding: '0px',
                                                            borderRadius: '5px',
                                                        }} >

                                                        <LenderCard key={index} lender={lender} final={final} own={own} />
                                                    </Box>
                                                    <Space h="md" />
                                                </>
                                            ))
                                        ) : (
                                            <Text>No lender found</Text>
                                        )}

                                    </Paper>

                                    {matchesMobile && mefinal && (
                                        <Button
                                            onClick={handleOpenReviewModal}
                                            variant="outline"
                                            color="secondary"
                                            fullWidth
                                        >Reviews Loans
                                        </Button>
                                    )}
                                </Stack>
                            </Grid.Col>
                        </Grid>


                    </Container>
                ) : (
                    <NotFound />
                )}
            </Box>
            {/* Modal for bidding */}
            <ReviewModal
                opened={openedReviewModal}
                onClose={handleCloseReviewModal}
                loanId={Loans?._id} // Pass the loan ID to the modal
                onReviewSubmit={handleReviewSubmit} // Pass the refresh handler
            />
            <Modal
                opened={updatemodal}
                onClose={closeupdatemodal}
                title="Update Loan"
                size="lg"
            >
                <Stack>
                    <NumberInput
                        label="Target Amount"
                        placeholder="Enter Target Amount"
                        value={targetAmount}
                        onChange={setTargetAmount}
                        min={0}
                    />
                    <DateInput
                        label="Deadline Date"
                        placeholder="Select Deadline"
                        value={new Date(deadlineDate)}
                        onChange={setDeadlineDate}
                    />
                    <Select
                        label="EMI Type"
                        placeholder="Select EMI Type"
                        data={[
                            { value: 'EMI', label: 'EMI' },
                            { value: 'One Time', label: 'One Time' },
                            // { value: 'Wish', label: 'Wish' },
                        ]}
                        value={Emi}
                        onChange={setemitype}
                    />
                    <Group mt="lg" position="right">
                        <Button onClick={handleupdate}>Submit</Button>
                    </Group>
                </Stack>
            </Modal>


            <Modal
                opened={bidModalOpened}
                onClose={closeBidModal}
                title="Bid for Lend"
                size="lg">
                <Stack>
                    <Select
                        label="EMI Type"
                        placeholder="Select EMI Type"
                        data={[
                            { value: 'EMI', label: 'EMI' },
                            { value: 'One Time', label: 'One Time' },
                            // { value: 'Wish', label: 'Wish' },
                        ]}
                        value={bidType}
                        onChange={setBidType}
                    />
                    <DateInput
                        label="Maximum Time"
                        placeholder="Select Date"
                        value={maxTime}
                        onChange={setMaxTime}
                    />
                    <NumberInput
                        label="Interest (%)"
                        placeholder="Enter Interest"
                        value={interest}
                        onChange={setInterest}
                        precision={2}
                        min={0}
                        max={100}
                    />
                    <Group mt="lg" position="right">
                        <Button onClick={handleBidSubmit}>Submit</Button>
                    </Group>
                </Stack>
            </Modal>

            {/* Modal for sharing */}
            <Modal
                opened={opened}
                onClose={close}
                title="Share Loan with Friends"
                size="lg"
            >
                <Group>
                    {/* Implement your sharing functionality here */}
                </Group>
            </Modal>
        </>
    );
};

export default LoanDetailsPage;