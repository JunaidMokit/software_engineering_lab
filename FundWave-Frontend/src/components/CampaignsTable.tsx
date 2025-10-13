import { ICampaign } from "../types";
import { Avatar, Group, Text } from "@mantine/core";
import { DataTable } from "mantine-datatable";
import { useEffect, useState } from "react";

const PAGE_SIZE = 10;

const CampaignsTable = ({ id }) => {
  const [page, setPage] = useState(1);
  const [records, setRecords] = useState([]);
  const [campaignsData, setCampaignsData] = useState([]);

  // Fetch campaign data
  const fetchData = async () => {
    try {
      const response = await fetch("http://localhost:3000/api/campaign");
      if (!response.ok) {
        throw new Error("Network response was not ok");
      }
      const data = await response.json();
      
      // Filter campaigns by username and sort by creation time
      const filteredCampaigns = data
        .filter((campaign) => campaign.username === id)
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

      setCampaignsData(filteredCampaigns);
      setRecords(filteredCampaigns.slice(0, PAGE_SIZE));

      // Now fetch the raised amounts for these campaigns
      await findraised(filteredCampaigns);

    } catch (error) {
      console.error("Error fetching campaign data:", error);
    }
  };
  const [donators, setDonators] = useState(0);
  // Fetch the raised amount for each campaign
  const fetchCampaignraised = async (_id: string) => {
    try {
      const donationResponse = await fetch(`http://localhost:3000/api/fundpayments/${_id}`);

      if (!donationResponse.ok) {
        throw new Error("Network response was not ok");
      }

      const donationData = await donationResponse.json();
      setDonators(donationData.length);
      const totalAmountRaised = donationData
        .map((d: any) => d.Amount)
        .reduce((a: number, b: number) => a + b, 0);
        return { totalAmountRaised, donators: donationData.length };
    } catch (error) {
      console.error("Error fetching donation data:", error);
      return { totalAmountRaised: 0, donators: 0 };
    }
  };

  // Update each campaign with the total raised amount
  const findraised = async (campaigns: ICampaign[]) => {
    const updatedCampaigns = await Promise.all(
      campaigns.map(async (campaign) => {
        const raisedAmount = await fetchCampaignraised(campaign._id);
        return { ...campaign, amountRaised: raisedAmount.totalAmountRaised, donators: raisedAmount.donators };
      })
    );

    setCampaignsData(updatedCampaigns);
    setRecords(updatedCampaigns.slice(0, PAGE_SIZE));
  };

  useEffect(() => {
    fetchData();
  }, [id]);

  useEffect(() => {
    const from = (page - 1) * PAGE_SIZE;
    const to = from + PAGE_SIZE;
    setRecords(campaignsData.slice(from, to));
  }, [page, campaignsData]);

  return (
    <DataTable
      columns={[
        {
          accessor: "createdBy",
          render: ({ username, createdByImage }: ICampaign) => (
            <Group>
              <Avatar src={createdByImage} alt={`${username} profile avatar`} size="sm" radius="xl" />
              <Text>{username}</Text>
            </Group>
          ),
        },
        { accessor: "title" },
        { accessor: "category" },
        {
          accessor: "amountRaised",
          render: ({ amountRaised }: ICampaign) => (
            <Text>{amountRaised ? `$${amountRaised?.toLocaleString()}` : "$0"}</Text>
          ),
        },
        {
            accessor: "Amount",
            render: ({ Amount }: ICampaign) => (
              <Text>{(Amount === 0 || !Amount) ? "Unlimited" : `$${Amount?.toLocaleString()}`}</Text>
            )
          },
          {
            accessor: "Donators",
            render: ({ donators }: ICampaign) => (
                <Text>{donators}</Text>
              )
            },       {
            accessor: "View Details",
            render: ({ _id }: ICampaign) => (
              <a href={`/campaigns/${_id}`} style={{ textDecoration: "none", color: "blue" }}>
                View
              </a>
            )
          }
        ]}
      records={records}
      totalRecords={campaignsData.length}
      recordsPerPage={PAGE_SIZE}
      page={page}
      onPageChange={(p) => setPage(p)}
      highlightOnHover
      verticalSpacing="sm"
    />
  );
};

export default CampaignsTable;
