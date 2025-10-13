import {Box, BoxProps, TextProps, Title, TitleProps} from '@mantine/core'
import {CampaignCard, TitleBadge} from "../../components";
import {Carousel} from "@mantine/carousel";
import {useState, useEffect} from 'react';
import campaignsData from "../../data/Campaigns.json";
import LoanCard from '../../components/LoanCard';

interface IProps {
    boxProps: BoxProps
    titleProps?: TitleProps,
    subtitleProps?: TextProps
}

const Loan = ({boxProps, titleProps}: IProps) => {

      const [loansData, setLoansData] = useState([{ id: 0 ,data:[{}]}]);
  
        // Function to fetch loan data
        const fetchLoanData = async () => {
          try {
            const response = await fetch('http://localhost:3000/api/loans'); // Adjust the URL if needed
  
            if (!response.ok) {
              throw new Error('Network response was not ok');
            }
            const data = await response.json();
           setLoansData(data);
          } catch (error) {
            console.error('Error fetching loan data:', error);
          }
        };
        useEffect(() => {
          fetchLoanData();
        }, []);
    const slides = loansData.map(c => (<Carousel.Slide key={c.id}><LoanCard data={c}/></Carousel.Slide>))

    return (
        <Box {...boxProps}>
            <TitleBadge title="Happening near you"/>
            <Title {...titleProps}>Find Loan</Title>
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

export default Loan;
