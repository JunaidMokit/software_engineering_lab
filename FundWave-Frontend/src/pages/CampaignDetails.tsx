import { useParams } from "react-router-dom";
import { useEffect, useState } from "react";
import { ICampaign } from "../types";
import campaignsData from "../data/Campaigns.json";
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
  Paper,
  PaperProps,
  Progress,
  Stack,
  Text,
  TextProps,
  Title,
  TitleProps,
  UnstyledButton,
} from "@mantine/core";
import { IconFlag, IconHeart, IconHeartFilled, IconSeparator, IconShare } from "@tabler/icons-react";
import { useDisclosure, useMediaQuery, useToggle } from "@mantine/hooks";
import { BackButton, DonationDrawer, NotFound, ShareModal, UserCard } from "../components";
import { Helmet } from "react-helmet";
import * as dayjs from "dayjs";
import * as LocalizedFormat from "dayjs/plugin/localizedFormat";
import { notifications } from "@mantine/notifications";
import UpdateModal from "../pages/UpdateModal";
import api from '../util/api';
interface IDonation {
  campaignid: string;
  Amount: number;
  give:string;
  createdAt: Date;
  tip: number;
}

const CampaignDetailsPage = (): JSX.Element => {
  dayjs.extend(LocalizedFormat);
  const { id } = useParams();
  const [campaign, setCampaign] = useState<ICampaign>();
  const [donations, setDonations] = useState<IDonation[]>([]);
  const [opened, { open, close }] = useDisclosure(false);
  const [donateOpened, { open: donateOpen, close: donateClose }] = useDisclosure(false);
  const [following, setFollowing] = useToggle();
  const matchesMobile = useMediaQuery("(max-width: 768px)");

  const paperProps: PaperProps = {
    p: "md",
    shadow: "sm",
  };
  const titleProps: TitleProps = {
    size: 32,
    weight: 700,
    transform: "capitalize",
    sx: { lineHeight: "40px" },
  };

  const subTitleProps: TextProps = {
    size: 20,
    weight: 600,
    sx: { lineHeight: "28px" },
  };

  const iconSize = 18;
  
  const fetchCampaignData = async () => {
    if (id) {
      try {
        const response = await fetch(`http://localhost:3000/api/campaign/${id}`);
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        const data = await response.json();
        setCampaign(data);
      } catch (error) {
        console.error("Error fetching campaign data:", error);
      }
    }
  };


    const fetchDonationData = async () => {
      if (id) {
        try {
          const response = await fetch(`http://localhost:3000/api/fundpayments/${id}`);
          if (!response.ok) {
            throw new Error("Network response was not ok");
          }
          const data = await response.json();
          setDonations(data);
        } catch (error) {
          console.error("Error fetching donation data:", error);
        }
      }
    }
  useEffect(() => {
    fetchCampaignData();
    fetchDonationData();
  }, [id]);

  // Calculate raised amount and donors count
  const raisedAmount = donations.reduce((sum, donation) => sum + donation.Amount-donation.tip, 0);
  const donorsCount = donations.length;

  // Calculate days left and remaining amount if target is "deadline"
  const daysLeft = campaign?.target === "deadline" ? dayjs(campaign.deadlineDate).diff(dayjs(), "day") : null;
  const remainingAmount = campaign ? campaign.amount - raisedAmount : 0;
  const [updateOpened, { open: updateOpen, close: updateClose }] = useDisclosure(false);


  return (
    <>
      <Helmet>
        <title>{campaign?.title}</title>
      </Helmet>
      <Box>
        {campaign ? (
          <Container size="lg">
            <BackButton mb="md" />
            <Grid>
              <Grid.Col lg={8}>
                <Stack>
                  <Card padding="md" shadow="sm">
                    <Card.Section>
                      <Image src={`${api.img}${campaign.imageUrl}`} height={480} />
                    </Card.Section>
                    <Stack mt="md">
                      <Title>{campaign?.title}</Title>
                      {!matchesMobile ? (
                        <Flex gap="xs" align="center">
                          <Text size="sm">Fundraise campaign created by</Text>
                          <UnstyledButton component={Anchor}>
                            <Flex gap="xs" align="center">
                              <Avatar src={campaign?.createdByImage} radius="xl" size="sm" />
                              <Text size="sm">{campaign?.createdBy}</Text>
                            </Flex>
                          </UnstyledButton>
                          <IconSeparator size={18} />
                          <Text component={Anchor} size="sm">
                            {campaign?.country}
                          </Text>
                          <IconSeparator size={18} />
                          <Text component={Anchor} size="sm">
                            {campaign?.category}
                          </Text>
                        </Flex>
                      ) : (
                        <Stack>
                          <Flex gap="md">
                            <Text size="sm">Fundraise campaign created by</Text>
                            <UnstyledButton component={Anchor}>
                              <Flex gap="xs" align="center">
                                <Avatar src={campaign?.createdByImage} radius="xl" size="sm" />
                                <Text size="sm">{campaign?.createdBy}</Text>
                              </Flex>
                            </UnstyledButton>
                          </Flex>
                          <Group>
                            {/* <Text size="sm">
                              Location - <Anchor>{campaign?.country}</Anchor>
                            </Text> */}
                            <Text size="sm">
                              Category - <Anchor>{campaign?.category}</Anchor>
                            </Text>
                          </Group>
                        </Stack>
                      )}
                      <Text {...subTitleProps}>Our story</Text>
                      <Text size="sm" dangerouslySetInnerHTML={{ __html: campaign?.story || "" }} />
                    </Stack>
                  </Card>
                  <Paper {...paperProps}>
                    <Text {...subTitleProps} mb="sm">
                      Organizer
                    </Text>
                    <UserCard username={campaign?.username} />
                  </Paper>
                </Stack>
              </Grid.Col>
              <Grid.Col lg={4}>
                <Paper {...paperProps}>
                  <Stack spacing="md">
                    {/* <Flex justify="space-between" align="center">
                      <Title {...titleProps}>Donate Now {campaign.Amount}</Title>
                      <ActionIcon
                        variant="subtle"
                        onClick={open}
                        color="blue"
                        title="Share with your friends"
                        size="lg"
                      >
                        <IconShare size={iconSize} />
                      </ActionIcon>
                    </Flex> */}
                    {campaign?.condition === "Completed" ? (
                    <Button variant="outline" disabled fullWidth>
                        Campaign Completed
                        </Button>
                        ) : (
                    <Button onClick={donateOpen} fullWidth>
                      Donate
                    </Button>
                    )}
                    {campaign?.username === localStorage.getItem("username") && campaign?.condition !== "Completed" ? (
                      <>
                      <Divider />
                      <Button onClick={updateOpen} fullWidth>
                        Update Campaign
                      </Button>
                      </>
                    ) : null}

                    <Divider />                    {/* <Text size="lg" weight={500} align="center">
                      {campaign?.target === "no-deadline" ? "Raised Amount" : "Amount Remaining"}
                    </Text> */}
                    <Title align="center" size="lg">
                    <Text
                    fw={500}
                    align="center"
                    color={campaign?.target === "no-deadline" ? 'green' : 'red'}
                    >
                    {campaign?.target === "no-deadline"
                        ? `${raisedAmount.toLocaleString()} ৳ Raised`
                        : `${remainingAmount?remainingAmount.toLocaleString():0} ৳ Remaining`}
                    </Text>
                    </Title>
                    <Progress
                        value={campaign?.target === "no-deadline" ? 100 : Math.min((raisedAmount / campaign.amount) * 100, 100)}
                        size="xl"
                        label={`${campaign?.target === "no-deadline" ? 100 : Math.min((raisedAmount / campaign.amount) * 100, 100).toFixed(2)}%`}
                        />
                     {campaign?.target === "deadline" && (
                           <>
                            {campaign?.target === "deadline" && campaign.deadlineDate ? (
                            (() => {
                                const deadline = new Date(campaign.deadlineDate).getTime();
                                const now = Date.now();

                                const remainingTime = deadline - now;

                                const daysLeft = Math.floor(remainingTime / (1000 * 60 * 60 * 24));
                                const hoursLeft = Math.floor((remainingTime % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                                const minutesLeft = Math.floor((remainingTime % (1000 * 60 * 60)) / (1000 * 60));

                                // Calculate the percentage for the progress bar
                                const totalDays = Math.ceil(
                                (deadline - new Date(campaign.createdAt).getTime()) / (1000 * 60 * 60 * 24)
                                );
                                const daysLeftPercentage = (daysLeft / totalDays) *100;

                                return (
                                <>
                                    <Progress
                                    value={Math.max(daysLeftPercentage, 0)} // Ensure it does not go below 0%
                                    size="xl"
                                    // label={`${Math.max(daysLeftPercentage, 0).toFixed(2)}% Days Left`}
                                    label={`${daysLeft} days ${hoursLeft} hours ${minutesLeft} minutes left`}
                                    />
                                    {/* <Text size="sm" align="center" mt="xs">
                                    {daysLeft} days {hoursLeft} hours {minutesLeft} minutes left
                                    </Text> */}
                                </>
                                );
                            })()
                            ) : null}
                       
                      </>
                    )}
                     <Text fw={500} align="center">
                          {donorsCount} Donations
                        </Text>
                  </Stack>
                </Paper>
              </Grid.Col>
            </Grid>
          </Container>
        ) : (
          <NotFound />
        )}
        <DonationDrawer  campaign={campaign} opened={donateOpened} onClose={donateClose} iconSize={iconSize} />
        <UpdateModal id={campaign?._id} opened={updateOpened} onClose={updateClose} />

        {/* <ShareModal opened={opened} onClose={close} /> */}
      </Box>
    </>
  );
};


export default CampaignDetailsPage;
