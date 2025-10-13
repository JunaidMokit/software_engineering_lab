import {
    Box,
    BoxProps,
    Card,
    Container,
    createStyles,
    Grid,
    Image,
    SimpleGrid,
    Stack,
    Text,
    TextProps,
    Title,
    TitleProps
} from "@mantine/core";
import {TitleBadge} from "../../components";
import {Link} from "react-router-dom";

const useStyles = createStyles((theme) => ({
    feature: {
        padding: theme.spacing.lg,
        backdropFilter: `blur(16px) saturate(180%)`,
        backgroundColor: `rgba(255, 255, 255, 0.75)`,
        border: `none`,

        '&:hover': {
            backgroundColor: theme.colors.secondary[2]
        }
    },
}));

interface IProps {
    boxProps: BoxProps
    titleProps?: TitleProps,
    subtitleProps?: TextProps
}

const WaysToFundSection = ({boxProps, subtitleProps}: IProps) => {
    const {classes, cx, theme} = useStyles();

    return (
        <Box sx={{background: theme.colors.secondary[8], color: theme.white}} {...boxProps}>
            <Container fluid p={36}>
                <Grid>
                    <Grid.Col lg={4}>
                        <Stack spacing="xs" justify="center" sx={{height: '100%'}}>
                            <TitleBadge title="Make your impact"/>
                            <Title order={3}>FundWave Helps You For</Title>
                            <Text>Supercharge your fundraising efforts within our university,
                                Helping you raise more money with the help than you could elsewhere</Text>
                        </Stack>
                    </Grid.Col>
                    <Grid.Col lg={8}>
                        <SimpleGrid cols={3} breakpoints={[{maxWidth: 'sm', cols: 1}]} >
                            <Card
                                className={cx(classes.feature, 'card')}
                                shadow="md"
                                radius="sm"
                                component={Link}
                                to="/create-loan"
                            >
                                <Card.Section>
                                    <Image
                                        src="https://www.newagebd.com/files/records/news/202310/215069_164.jpg"/>
                                </Card.Section>
                                <Text mt="md" align="center" {...subtitleProps}>Academics</Text>
                            </Card>
                            <Card
                                className={cx(classes.feature, 'card')}
                                shadow="md"
                                radius="sm"
                                component={Link}
                                to="/create-campaign"
                            >
                                <Card.Section>
                                    <Image
                                        src="https://www.dailymessenger.net/media/imgAll/2024February/en/BRAC-2410010611.jpg"/>
                                </Card.Section>
                                <Text mt="md" align="center" {...subtitleProps}>Social Welfare</Text>
                            </Card>
                            <Card
                                className={cx(classes.feature, 'card')}
                                shadow="md"
                                radius="sm"
                                component={Link}
                                to="/create-campaign"
                            >
                                <Card.Section>
                                    <Image
                                        src="https://businessinspection.com.bd/wp-content/uploads/2022/07/NSUSSC-Successfully-Conducted-Flood-Relief-Distribution-1-1.jpg"/>
                                </Card.Section>
                                <Text mt="md" align="center" {...subtitleProps}>Disaster or Crisis</Text>
                            </Card>
                        </SimpleGrid>
                    </Grid.Col>
                </Grid>
            </Container>
        </Box>
    );
};

export default WaysToFundSection;
