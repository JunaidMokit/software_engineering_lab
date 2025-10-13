import { ILoans } from "../types";
import { Avatar, Group, Text } from "@mantine/core";
import { DataTable } from "mantine-datatable";
import { useEffect, useState } from "react";

const PAGE_SIZE = 10;

const LoansTable = ({ id ,type}) => {
  const [page, setPage] = useState(1);
  const [records, setRecords] = useState([]);
  const [loansData, setLoansData] = useState([]);
  const username = localStorage.getItem("username");
  // Fetch loan data
  const fetchData = async () => {
    try {
      const response = await fetch("http://localhost:3000/api/loans");
      if (!response.ok) {
        throw new Error("Network response was not ok");
      }
      const bid = await response.json();
      const bidd = await fetch(`http://localhost:3000/api/bids/user/${username}`);
      if (!bidd.ok) {
        throw new Error("Network response was not ok");
      }
      let bids = await bidd.json();
      bids = bids.data.map((bid: any) => bid.loanid);
      const finalbids= await fetch(`http://localhost:3000/api/bids/final/${username}`);
      if (!finalbids.ok) {
        throw new Error("Network response was not ok");
      }
      let finalbox = await finalbids.json();
      finalbox = finalbox.data.map((bid: any) => bid.loanid);

      // console.log(type);
      // console.log(bid);
      // console.log(bids);
      // console.log(finalbox);
      if (type === "Bids") {
        const filteredLoans = bid
            .filter((loan) => bids.includes(loan._id))
            .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        setLoansData(filteredLoans);
        setRecords(filteredLoans.slice(0, PAGE_SIZE));
        await findRaised(filteredLoans);
    } else if (type === "Final") {
        const filteredLoans = bid
            .filter((loan) => finalbox.includes(loan._id))
            .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        setLoansData(filteredLoans);
        setRecords(filteredLoans.slice(0, PAGE_SIZE));
        await findRaised(filteredLoans);
    } else {
        const filteredLoans = bid
            .filter((loan) => loan.username === id)
            .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        setLoansData(filteredLoans);
        setRecords(filteredLoans.slice(0, PAGE_SIZE));
        await findRaised(filteredLoans);
      }

    } catch (error) {
      console.error("Error fetching loan data:", error);
    }
  };


  const [donators, setDonators] = useState(0);

  // Fetch the raised amount for each loan
  const fetchLoanRaised = async (_id: string) => {
    try {
      const donationResponse = await fetch(`http://localhost:3000/api/bids/${_id}`);

      if (!donationResponse.ok) {
        throw new Error("Network response was not ok");
      }
      const biders = await donationResponse.json();
    //   setDonators(donationData.length);
    //   const totalAmountRaised = donationData
    //     .map((d: any) => d.Amount)
    //     .reduce((a: number, b: number) => a + b, 0);
    //   return { totalAmountRaised, donators: donationData.length };
    if(!biders.data){
        return 0;
    }
    return biders.data?.length;
    } catch (error) {
      console.error("Error fetching donation data:", error);
      return 0;
    }
  };
  // Update each loan with the total raised amount
  const findRaised = async (loans: ILoans[]) => {
    const updatedLoans = await Promise.all(
      loans.map(async (loan) => {
        const biders = await fetchLoanRaised(loan._id);
        return { ...loan, biders: biders };
      })
    );

    setLoansData(updatedLoans);
    setRecords(updatedLoans.slice(0, PAGE_SIZE));
  };

  useEffect(() => {
    fetchData();
  }, [id]);

  useEffect(() => {
    const from = (page - 1) * PAGE_SIZE;
    const to = from + PAGE_SIZE;
    setRecords(loansData.slice(from, to));
  }, [page, loansData]);
  
  return (
    <DataTable
      columns={[
        {
          accessor: "createdBy",
          render: ({ username, createdByImage }: ILoans) => (
            <Group>
              <Avatar src={createdByImage} alt={`${username} profile avatar`} size="sm" radius="xl" />
              <Text>{username}</Text>
            </Group>
          ),
        },
        { accessor: "title" },
        { accessor: "category" },
        {
          accessor: "Status",
          render: ({ condition }: ILoans) => (
            <Text>{condition}</Text>
          ),
        },
        {
          accessor: "Target Amount",
          render: ({ targetAmount }: ILoans) => (
            <Text>{targetAmount}</Text>
          ),
        },
        {
          accessor: "Biders",
          render: ({ biders }: ILoans) => <Text>{biders}</Text>,
        },
        {
          accessor: "View Details",
          render: ({ _id }: ILoans) => (
            <a href={`/loans/${_id}`} style={{ textDecoration: "none", color: "blue" }}>
              View
            </a>
          ),
        },
      ]}
      records={records}
      totalRecords={loansData.length}
      recordsPerPage={PAGE_SIZE}
      page={page}
      onPageChange={(p) => setPage(p)}
      highlightOnHover
      verticalSpacing="sm"
    />
  );
};

export default LoansTable;
