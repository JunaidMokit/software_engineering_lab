import {
    Box,
    BoxProps,
    Button,
    Card,
    createStyles,
    Image,
    PaperProps,
    SimpleGrid,
    Stack,
    Text,
    TextProps,
    Title,
    TitleProps
} from '@mantine/core';
import { Link } from 'react-router-dom'; // Import Link from react-router-dom
import { TitleBadge } from "../../components";

const useStyles = createStyles((theme) => ({
    feature: {
        padding: theme.spacing.lg,
        backdropFilter: `blur(16px) saturate(180%)`,
        backgroundColor: `rgba(255, 255, 255, 0.75)`,
        border: `1px solid rgba(209, 213, 219, 0.3)`
    },
}));

interface FeatureProps extends PaperProps {
    image: string;
    title: string;
    description: string;
    action: string;
}

const mockdata = [
    {
        image: 'https://scholarshipinindia.com.bd/uploads/event/event_1709129878.jpg',
        title: 'Help Investing in My Academic Future',
        description:
            'Help me achieve reach my academic dreams I am passionate about my studies, but I need your support to reach my goals. Your contributions will go directly towards my education, helping me focus on what matters most: learning and growing..',
        action: `Check out available student loans for contribution`
    },
    {
        image: 'https://www.sdsbd.org/wp-content/uploads/2023/10/IMG_3705-1.jpg',
        title: 'Help Me Reach Graduation',
        description:
            `Your support can make a difference I’m working hard to finish my degree, but financial barriers are standing in my way. With your help, I can cover the costs of tuition and fees, and get one step closer to graduation.`,
        action: 'Empower Students, Get Repaid Fairly'
    },
    {
        image: 'https://www.bracu.ac.bd/sites/default/files/news-image/SAF_Fall21.jpg',
        title: 'Crowdfunding for Recent Flood',
        description:
            `Your contribution can bring hope and recovery The recent floods have devastated homes and livelihoods. By contributing to this campaign, you can help families rebuild their homes and restore their lives.`,
        action: 'See crowdfunding options'
    },
    {
        image: 'https://outspoken.newagebd.com/files/img/202408/58abf1a455aaff4f1790de8441ed17e6.jpg',
        title: 'Stand with Us in This Time of Crisis',
        description:
            `Together, we can make a difference Our community is facing unprecedented damage from the floods. Your support can provide essential supplies, shelter, and relief to those in need.`,
        action: 'Find out how we can work together'
    },
];

function Feature({ image, title, description, action }: FeatureProps) {
    const { classes, cx } = useStyles();

    return (
        <Card className={cx(classes.feature, 'card')} shadow="md" radius="sm">
            <Card.Section>
                <Image src={image} height={240} fit="cover" />
            </Card.Section>
            <Stack spacing="sm" mt="md">
                <Title order={4}>{title}</Title>
                <Text size="sm">{description}</Text>
                <Button variant="subtle" color="secondary" component={Link} to="/loans">
                    {action}
                </Button>
            </Stack>
        </Card>
    );
}

interface IProps {
    boxProps: BoxProps;
    titleProps?: TitleProps;
    subtitleProps?: TextProps;
}

const FeaturesSection = ({ boxProps, subtitleProps }: IProps) => {
    const items = mockdata.map((item) => <Feature {...item} key={item.title} />);

    return (
        <Box {...boxProps}>
            <Box mb="lg">
                <TitleBadge title="What to Expect" />
                <Text {...subtitleProps}>
                    Our platform exists to support UIU students in need of whether crowdfunding for any crisis or seeking a student loan, we’re here to help you reach your goals with the support of your community. What dreams can we help you achieve?
                </Text>
            </Box>
            <SimpleGrid cols={2} spacing="lg" breakpoints={[{ maxWidth: 'md', cols: 2, spacing: 'sm' }]}>
                {items}
            </SimpleGrid>
        </Box>
    );
}

export default FeaturesSection;
