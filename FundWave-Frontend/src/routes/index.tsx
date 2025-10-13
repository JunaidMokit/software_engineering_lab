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
} from "../pages";
import {Navigate} from "react-router-dom";
import LoansPage from "../pages/Loans";
import CreateLoanPage from "../pages/CreateLoan";
import LoanDetailsPage from "../pages/LoanDetailsPage";
import DonationSucessPage from "../pages/PaymentDone";
import Chatbox from "../pages/ChatBox";
import ChatGO from "../pages/ChatBoss";
import PassChanger from '../pages/RegisterPage/ChangePass/PassChanger';
import Recovred from '../pages/RegisterPage/ForgetPassword/Recovered';
import EmailVerificationForm from '../pages/RegisterPage/ForgetPassword/OTPInput';
import Reset from '../pages/RegisterPage/ForgetPassword/Reset';

const RequireAuth = ({ children }: { children: JSX.Element }) => {
    const username = localStorage.getItem('username');
    return username ? children : <Navigate to="/login" />;
};
import Public_Chat from "../layout/Public_Chat";
import {DashboardLayout, PublicLayout} from "../layout";
import LoanPaymentDone from "../pages/LoanPaymentDone";
import Trans from "../pages/Trans";
import Profilebox from "../pages/Profilebox";
import RedirectToUser from "../pages/Go";
import { GoDash } from "react-icons/go";

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
                element: (
                    <RequireAuth>
                    <CampaignDetailsPage/>
                </RequireAuth>
                ),
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
                element: (
                    <RequireAuth>
                    <LoanDetailsPage/>
                </RequireAuth>
                ),
                errorElement: <DetailError404Page/>
            }
            ,
            {
                path: "trans/:id",
                element: (
                    <RequireAuth>
                    <Trans/>
                </RequireAuth>
                ),
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
                element: (
                    <RequireAuth>
                    <GoDash/>
                   </RequireAuth>
                ),
                errorElement: <Error404Page/>,

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
                element: (
                    <RequireAuth>
                    <CreateCampaignPage />
                </RequireAuth>
                ),
                errorElement: <Error404Page/>,

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
                element: (
                    <RequireAuth>
                    <CreateLoanPage />
                </RequireAuth>
                )

            }
        ]
    },
    {
        path: "payment",
        element: <PublicLayout />,
        children: [
            {
                path: "",
                index: true,
                element: <LoansPage />,
                errorElement: <Error404Page />,
            },
            {
                path: "success/:id",
                element: (
                    <RequireAuth>
                        <DonationSucessPage />
                    </RequireAuth>
                ),
                errorElement: <DetailError404Page />
            },
            
            {
                path: "success/loan/:id",
                element: (
                    <RequireAuth>
                        <LoanPaymentDone />
                    </RequireAuth>
                ),
                errorElement: <DetailError404Page />
            },
            
        ]
    },
    
    {
        path: "chat",
        element: <Public_Chat/>,
        children: [
            {
                path: "",
                element: (
                    <RequireAuth>
                    <RedirectToUser/>
                </RequireAuth>
                ),
                errorElement: <Error404Page/>,
            },
            
            {
                path: ":fnd",
                element: (
                    <RequireAuth>
                    <Chatbox/>
                </RequireAuth>
                ),
                errorElement: <DetailError404Page/>
            }
            ,
            {
                path: "msg/:id",
                element: (
                    <RequireAuth>
                    <ChatGO/>
                </RequireAuth>
                ),
                errorElement: <DetailError404Page/>
            }
        ]
    },
    {
        path: "profile",
        element: <DashboardLayout/>,
        errorElement: <Error404Page/>,
        children: [
            {
                path: ':id',
                index: true,
                element: (
                    <RequireAuth>
                    <Profilebox/>
                </RequireAuth>
                ),
                errorElement: <Error404Page/>,

            }
        ]
    },{
        path: "forgot",
        element: <DashboardLayout/>,
        errorElement: <Error404Page/>,
        children: [
            {
                path: '',
                index: true,
                element: (
                    <PassChanger/>
                ),
                errorElement: <Error404Page/>,

            }, {
                path: 'recovered',
                index: true,
                element: (
                    <Recovred/>
                ),
                errorElement: <Error404Page/>,

            },
            {
                path: 'otp',
                index: true,
                element: (
                    <EmailVerificationForm/>
                ),
            },
            {
                path: 'reset',
                index: true,
                element: (
                    <Reset/>
                ),
                errorElement: <Error404Page/>,
            }
        ]
    },
    
]);


export default router;
