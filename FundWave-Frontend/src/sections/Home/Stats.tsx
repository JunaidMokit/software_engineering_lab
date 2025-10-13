import {Box, BoxProps, Paper, PaperProps, SimpleGrid, Text, TextProps, Title, TitleProps} from "@mantine/core";
import {TitleBadge} from "../../components";

const mockData = [
    {
        amount: '4 Cr',
        description: 'We have raised an impressive amounts of funds. Help use continue to grow and reach our ultimate goal.'
    },
    {
        amount: '4k',
        description: 'Over 4kK campaigns are funded. Join us and be a part of our success story.'
    },
    {
        amount: '400',
        description: 'We have more than 400 active campaigns. Help us continue to made vision into reality.'
    }
]

interface IStatsProps extends PaperProps {
    amount: string
    description: string
}

function Stats({amount, description}: IStatsProps) {
    return (
        <Paper
            p="md"
            shadow="md"
            radius="sm"
            sx={{
                backdropFilter: `blur(16px) saturate(180%)`,
                backgroundColor: `rgba(255, 255, 255, 0.75)`,
                border: `1px solid rgba(209, 213, 219, 0.3)`
            }}>
            <Title size={36} mb="md">{amount}+</Title>
            <Text size="sm">{description}</Text>
        </Paper>
    )
}

interface IProps {
    boxProps: BoxProps
    titleProps?: TitleProps,
    subtitleProps?: TextProps
}

const StatsSection = ({boxProps, subtitleProps, titleProps}: IProps) => {
    const items = mockData.map((item) => <Stats {...item} key={item.description}/>)

    return (
        <Box {...boxProps}>
            <Box mb="lg">
                <TitleBadge title="make a difference"/>
                <Title {...titleProps}>large pool of opportunities available</Title>
                <Text {...subtitleProps}>With our crowdfunding platform, you can support the students and causes you
                    care about most</Text>
            </Box>
            <SimpleGrid
                cols={3}
                spacing="lg"
                breakpoints={[
                    {maxWidth: 'md', cols: 3, spacing: 'md'},
                    {maxWidth: 'sm', cols: 1, spacing: 'sm'},
                ]}
            >
                {items}
            </SimpleGrid>
        </Box>
    );
};

export default StatsSection;
