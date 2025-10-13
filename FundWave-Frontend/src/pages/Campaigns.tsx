import {
    Box,
    BoxProps,
    Container,
    Flex,
    Select,
    SimpleGrid,
    Stack,
    TextInput,
    Title,
    TitleProps,
    Pagination,
  } from "@mantine/core";
  import { CampaignCard } from "../components";
  import { Helmet } from "react-helmet";
  import { useMediaQuery } from "@mantine/hooks";
  import { useState, useEffect } from "react";
  
  const CampaignsPage = (): JSX.Element => {
    const matchesMobile = useMediaQuery("(max-width: 768px)");
  
    const boxProps: BoxProps = {
      mt: matchesMobile ? 4 : 24,
      mb: matchesMobile ? 4 : 48,
      py: matchesMobile ? 16 : 24,
    };
  
    const titleProps: TitleProps = {
      size: 32,
      weight: 700,
      mb: "lg",
      transform: "capitalize",
      sx: { lineHeight: "40px" },
    };
  
    const [campaigns, setCampaigns] = useState<any[]>([]);
    const [filteredCampaigns, setFilteredCampaigns] = useState<any[]>([]);
    const [searchTerm, setSearchTerm] = useState<string>("");
    const [itemsPerPage, setItemsPerPage] = useState<number>(10);
    const [activePage, setActivePage] = useState<number>(1);
    const [sortOrder, setSortOrder] = useState<string>("featured");
  
    // Fetch campaign data
    const fetchData = async () => {
      try {
        const response = await fetch("http://localhost:3000/api/campaign");
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        const data = await response.json();
        setCampaigns(data);
        setFilteredCampaigns(data);
      } catch (error) {
        console.error("Error fetching campaign data:", error);
      }
    };
  
    // Fetch data when the component mounts
    useEffect(() => {
      fetchData();
    }, []);
    const fetchCampaignraised = async (_id: string) => {
        try {
          const campaignResponse = await fetch(`http://localhost:3000/api/campaign/${_id}`);
          const donationResponse = await fetch(`http://localhost:3000/api/fundpayments/${_id}`);
    
          if (!campaignResponse.ok || !donationResponse.ok) {
            throw new Error("Network response was not ok");
          }
    
          const donationData = await donationResponse.json();
          const total = donationData.map((d: any) => d.Amount).reduce((a: number, b: number) => a + b, 0);
          const tip = donationData.map((d: any) => d.tip).reduce((a: number, b: number) => a + b, 0);
          const totalAmountRaised=total-tip;
          console.log(totalAmountRaised,tip);
          return totalAmountRaised;
        } catch (error) {
          console.error("Error fetching campaign or donation data:", error);
          return 0;
        }
      };
      // Function to update each campaign with the amount raised (popular field)
      const findraised = async () => {
        const updatedCampaigns = await Promise.all(
          campaigns.map(async (campaign) => {
            const raisedAmount = await fetchCampaignraised(campaign._id);
            return { ...campaign, popular: raisedAmount };
          })
        );
        setCampaigns(updatedCampaigns);
        setFilteredCampaigns(updatedCampaigns);
      };
    

    
      useEffect(() => {
        if (campaigns.length > 0) {
          findraised(); 
        }
      }, []);
        // Handle search
    const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
      const term = e.target.value.toLowerCase();
      setSearchTerm(term);
      if(term == "") {
        setFilteredCampaigns(campaigns);
        return;
        }
      const filtered = filteredCampaigns.filter((campaign) =>
        campaign.title.toLowerCase().includes(term)||campaign.category.toLowerCase().includes(term)||campaign.username.toLowerCase().includes(term)
      );
      setFilteredCampaigns(filtered);
      setActivePage(1); // Reset to the first page on new search
    }
    // Handle sorting
    const handleSort = (sortValue: string) => {
      setSortOrder(sortValue);
  
      let sortedCampaigns = [...filteredCampaigns];
      if (sortValue === "latest") {
        sortedCampaigns.sort(
          (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
        );
      } else if (sortValue === "popular") {
        sortedCampaigns.sort((a, b) => b.popular - a.popular);
      }else if (sortValue === "Completed") {
        const completedCampaigns = sortedCampaigns.filter((campaign) => campaign.condition === "Completed");
        sortedCampaigns = completedCampaigns;
        console.log("complted size",sortedCampaigns.length);
      }
      setFilteredCampaigns(sortedCampaigns);
    };
  
    // Paginate data based on items per page and active page
    const paginatedCampaigns = filteredCampaigns.slice(
      (activePage - 1) * itemsPerPage,
      activePage * itemsPerPage
    )
    const items = paginatedCampaigns.map((campaign) => (
      <CampaignCard key={campaign.id} data={campaign} showActions={true} />
    ));
  
    return (
      <>
        <Helmet>
          <title>Discover campaigns to fund</title>
        </Helmet>
        <Box>
          <Container size="lg">
            <Stack>
              <Box {...boxProps}>
                <Title {...titleProps} align="center">
                  Discover campaigns to fund
                </Title>
              </Box>
              <Flex
                justify="space-between"
                gap={{ base: "sm", sm: "lg" }}
                direction={{ base: "column-reverse", sm: "row" }}
              >
                <TextInput
                  placeholder="Search campaigns..."
                  value={searchTerm}
                  onChange={handleSearch}
                  sx={{ width: 500 }}
                />
                <Flex
                  align="center"
                  gap="sm"
                  justify={{ base: "space-between", sm: "flex-start" }}
                >
                  <Select
                    label=""
                    placeholder="Show"
                    value={itemsPerPage.toString()}
                    onChange={(value) => {
                      setItemsPerPage(Number(value));
                      setActivePage(1); // Reset to first page on items per page change
                    }}

                    data={[
                      { value: "10", label: "Show: 10" },
                      { value: "25", label: "Show: 25" },
                      { value: "50", label: "Show: 50" },
                      { value: "100", label: "Show: 100" },
                    ]}
                  />
                  <Select
                    label=""
                    placeholder="Sort by"
                    value={sortOrder}
                    onChange={handleSort}
                    data={[
                      { value: "latest", label: "Sort by: Latest" },
                      { value: "popular", label: "Sort by: Popular" },
                      { value: "Completed", label: "Sort by: Completed" },

                    ]}
                  />
                </Flex>
              </Flex>
              <SimpleGrid
                cols={3}
                spacing="lg"
                breakpoints={[
                  { maxWidth: "md", cols: 2, spacing: "md" },
                  { maxWidth: "sm", cols: 1, spacing: 0 },
                ]}
              >
                {items}
              </SimpleGrid>
              <Pagination
                value={activePage}
                onChange={setActivePage}
                total={Math.ceil(filteredCampaigns.length / itemsPerPage)}
                position="center"
                mt="lg"
              />
            </Stack>
          </Container>
        </Box>
      </>
    );
  };
  
  export default CampaignsPage;
  