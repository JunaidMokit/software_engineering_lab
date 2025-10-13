import {createBrowserRouter} from "react-router-dom";
import {
    CampaignDetailsPage,
    CampaignsPage,
    CreateCampaignPage,
    DashboardPage,
    DetailError404Page,
    Error404Page,
    HomePage,
    HowItWorksPage,
    LoginPage,
    SignupPage,
} from ".";
import LoansPage from "./Loans";
import CreateLoanPage from "./CreateLoan";



import {DashboardLayout, PublicLayout} from "../layout";
import React from "react";
const router = createBrowserRouter([
    {
        path: "/",
        element: <PublicLayout compressedNav/>,
        errorElement: <Error404Page/>,
        children: [
            {
                path: '',
                index: true,
                element: <HomePage/>
            }
        ]
    },
    {
        path: "login",
        element: <LoginPage/>,
        errorElement: <Error404Page/>,
    },
    {
        path: "signup",
        element: <SignupPage/>,
        errorElement: <Error404Page/>,
    },
    {
        path: "how-it-works",
        element: <PublicLayout/>,
        errorElement: <Error404Page/>,
        children: [
            {
                path: '',
                index: true,
                element: <HowItWorksPage/>
            }
        ]
    },
    {
        path: "campaigns",
        element: <PublicLayout/>,
        children: [
            {
                path: "",
                index: true,
                element: <CampaignsPage/>,
                errorElement: <Error404Page/>,
            },
            {
                path: ":id",
                element: <CampaignDetailsPage/>,
                errorElement: <DetailError404Page/>
            }
        ]
    },
    {
        path: "loans",
        element: <PublicLayout/>,
        children: [
            {
                path: "",
                index: true,
                element: <LoansPage/>,
                errorElement: <Error404Page/>,
            },
            {
                path: ":id",
                element: <CampaignDetailsPage/>,
                errorElement: <DetailError404Page/>
            }
        ]
    },
    {
        path: "dashboard",
        element: <DashboardLayout/>,
        errorElement: <Error404Page/>,
        children: [
            {
                path: '',
                index: true,
                element: <DashboardPage/>
            }
        ]
    },
    {
        path: "create-campaign",
        element: <DashboardLayout/>,
        errorElement: <Error404Page/>,
        children: [
            {
                path: '',
                index: true,
                element: <CreateCampaignPage/>
            }
        ]
    },{
        path: "create-loan",
        element: <DashboardLayout/>,
        errorElement: <Error404Page/>,
        children: [
            {
                path: '',
                index: true,
                element: <CreateLoanPage/>
            }
        ]
        
    },
   
]);


export default router;
