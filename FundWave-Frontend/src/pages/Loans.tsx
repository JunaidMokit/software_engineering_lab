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
  import LoanCard from "../components/LoanCard";
  import { Helmet } from "react-helmet";
  import { useMediaQuery } from "@mantine/hooks";
  import { useState, useEffect } from "react";
  
  const LoansPage = (): JSX.Element => {
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
  
    const [loansData, setLoansData] = useState<any[]>([]);
    const [filteredLoans, setFilteredLoans] = useState<any[]>([]);
    const [searchTerm, setSearchTerm] = useState<string>("");
    const [itemsPerPage, setItemsPerPage] = useState<number>(10);
    const [activePage, setActivePage] = useState<number>(1);
    // const [sortOrder, setSortOrder] = useState<string>("latest");
    const [sortOrder, setSortOrder] = useState<string>("featured");
  
    // Function to fetch loan data
    const fetchLoanData = async () => {
      try {
        const response = await fetch("http://localhost:3000/api/loans");
  
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        const data = await response.json();
        setLoansData(data);
        setFilteredLoans(data);

      } catch (error) {
        console.error("Error fetching loan data:", error);
      }
    };
    // Fetch data when the component mounts
    useEffect(() => {
      fetchLoanData();
    }, []);

    

  // Fetch number of bids for each loan and add popularity field
  const findPeople = async (loanId: string) => {
    try {
      const response = await fetch(`http://localhost:3000/api/bids/${loanId}`);
      const data = await response.json();

      if (data.noBids) {
        return 0;
      }
      return data.data.length;
    } catch (error) {
      console.error("Error fetching user data:", error);
      return 0;
    }
  };
  // Function to attach popularity to each loan
  const find = async () => {
    const updatedLoans = await Promise.all(
      loansData.map(async (loan) => {
        const popularity = await findPeople(loan._id); 
        return { ...loan, popularity }; 
      })
    );

    setLoansData(updatedLoans);
    setFilteredLoans(updatedLoans);
  };



  useEffect(() => {
    if (loansData.length > 0) {
      find();
    }
  }, []);



    // Function to handle search
    const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
      console.log(e.target.value);
      console.log(loansData);
      const term = e.target.value.toLowerCase();
      setSearchTerm(term);
      if (!term ||  term =="") {
        setFilteredLoans(loansData);
        return;
      }
      const filtered = filteredLoans.filter((loan) =>
        loan.title.toLowerCase().includes(term)||loan.category.toLowerCase().includes(term)||loan.condition.toLowerCase().includes(term)||loan.username.toLowerCase().includes(term)
      );
      setFilteredLoans(filtered);
      setActivePage(1); // Reset to first page on new search
    };
  
    // Function to handle sorting
    const handleSort = (sortValue: string) => {
      setSortOrder(sortValue);
  
      let sortedLoans = [...filteredLoans];
      if (sortValue === "latest") {
        sortedLoans.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
      } else if (sortValue === "popular") {
        sortedLoans.sort((a, b) => b.popularity - a.popularity);
      }else if (sortValue === "Completed") {
        const completedCampaigns = sortedLoans.filter((campaign) => campaign.condition === "Completed");
        sortedLoans = completedCampaigns;
        console.log("complted size",sortedLoans.length);
      }
      if (sortValue != "Completed") {
        const completedCampaigns = sortedLoans.filter((campaign) => campaign.condition != "Completed");
        sortedLoans = completedCampaigns;
        console.log("complted size",sortedLoans.length);
      }      setFilteredLoans(sortedLoans);
    };
    useEffect(() => {
      handleSort(sortOrder);
    }, []);

  
    // Paginate data based on items per page and active page
    const paginatedLoans = filteredLoans.slice(
      (activePage - 1) * itemsPerPage,
      activePage * itemsPerPage
    );
  
    const items = paginatedLoans.map((loan) => (
      <LoanCard key={loan.id} data={loan} showActions={true} />
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
                  Discover Loans to Lend
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
                <Flex align="center" gap="sm" justify={{ base: "space-between", sm: "flex-start" }}>
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
                page={activePage}
                onChange={setActivePage}
                total={Math.ceil(filteredLoans.length / itemsPerPage)}
                position="center"
                mt="lg"
              />
            </Stack>
          </Container>
        </Box>
      </>
    );
  };
  
  export default LoansPage;
  