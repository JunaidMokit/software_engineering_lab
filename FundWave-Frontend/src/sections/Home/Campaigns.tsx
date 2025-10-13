import {Box, BoxProps, TextProps, Title, TitleProps} from '@mantine/core'
import {CampaignCard, TitleBadge} from "../../components";
import {Carousel} from "@mantine/carousel";

import { useEffect, useState } from 'react';

interface IProps {
    boxProps: BoxProps
    titleProps?: TitleProps,
    subtitleProps?: TextProps
}

const CampaignsSection = ({boxProps, titleProps}: IProps) => {
    const [campaignsData, setCampaignsData] = useState([{ id: 0 ,data:[{}]}]);
    const findcampaigns = async () => {
        try {
            const response = await fetch('http://localhost:3000/api/campaign');

            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            const data = await response.json();
            setCampaignsData(data);
        } catch (error) {
            console.error('Error fetching campaign data:', error);
        }
    }
    useEffect(() => {
        findcampaigns();
    }, []);
    const slides = campaignsData.map(c => (<Carousel.Slide key={c.id}><CampaignCard data={c}/></Carousel.Slide>))
    return (
        <Box {...boxProps}>
            <TitleBadge title="Happening near you"/>
            <Title {...titleProps}>Fundraisers in our UIU</Title>
            <Carousel
                slideSize="45%"
                align="start"
                slideGap="md"
                breakpoints={[
                    {maxWidth: 'md', slideSize: '45%'},
                    {maxWidth: 'sm', slideSize: '100%', slideGap: 0},
                ]}
            >
                {slides}
            </Carousel>
        </Box>
    );
};

export default CampaignsSection;
