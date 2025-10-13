import { Helmet } from "react-helmet";
import {
    ActionIcon,
    Alert,
    Anchor,
    Box,
    Button,
    Checkbox,
    Container,
    Flex,
    Group,
    NumberInput,
    Paper,
    PaperProps,
    Radio,
    SegmentedControl,
    Select,
    SimpleGrid,
    Stack,
    Stepper,
    Text,
    TextInput,
    Title,
    TitleProps,
    useMantineTheme
} from "@mantine/core";
import { Link } from 'react-router-dom';
import { RichTextEditor } from '@mantine/tiptap';
import { useEditor } from '@tiptap/react';
import Highlight from '@tiptap/extension-highlight';
import StarterKit from '@tiptap/starter-kit';
import Underline from '@tiptap/extension-underline';
import TextAlign from '@tiptap/extension-text-align';
import Superscript from '@tiptap/extension-superscript';
import SubScript from '@tiptap/extension-subscript';
import React, { forwardRef, useState } from "react";
import { DateInput } from "@mantine/dates";
import { useNavigate } from "react-router-dom";
import {
    IconBrandApple,
    IconBrandFacebook,
    IconBrandGoogle,
    IconBrandLinkedin,
    IconBrandPaypal,
    IconBrandTwitter,
    IconBrandWhatsapp,
    IconBrandYoutube,
    IconCalendar,
    IconCheck,
    IconChevronLeft,
    IconChevronRight,
    IconCurrencyDollar,
    IconCurrencyTaka,
    IconInfoCircleFilled,
    IconLink,
    IconMail,
    IconPlus,
    IconTrash
} from "@tabler/icons-react";
import CategoryLoan from "../components/CategoryLoan";
import { randomId } from "@mantine/hooks";
import { useForm } from "@mantine/form";
import {CategorySelect, CountrySelect, CurrencySelect, FileDropzone} from "../components";
//const [isSubmitting, setIsSubmitting] = useState(false); // Add state to track form submission

interface ISocialProps {
    icon: React.FC<any>;
    title: React.ReactNode;
}

const SocialSelectItem = forwardRef<HTMLDivElement, ISocialProps>(
    ({ title, icon: Icon, ...others }: ISocialProps, ref) => (
        <div ref={ref} {...others}>
            <Group noWrap>
                <Icon size={18} stroke={1.5} />
                <Text size="sm" transform="capitalize">{title}</Text>
            </Group>
        </div>
    )
);
const CreateLoanPage = () => {
    const navigate = useNavigate();

    const theme = useMantineTheme();
    const [active, setActive] = useState(0);
    const [target, setTarget] = useState('deadline');
    const [deadlineDate, setDeadlineDate] = useState<Date | null>(null);
    const [donationType, setDonationType] = useState('any');
    const [minimumCheck, setMinimumCheck] = useState(false);
    const [bkashNumber, setBkashNumber] = useState('');
    const [nagadNumber, setNagadNumber] = useState('');
    const [rocketNumber, setRocketNumber] = useState('');
    const editor = useEditor({
        extensions: [
            StarterKit,
            Underline,
            Link,
            Superscript,
            SubScript,
            Highlight,
            TextAlign.configure({ types: ['heading', 'paragraph'] }),
        ],
        content: '',
    });

    const socialForm = useForm({
        initialValues: {
            title: '',
            category: '',
            targetAmount: '',
            deadlineDate: '',
            donationType: '',
            interest: '',
            profilePicture: '',
            firstName: '',
            lastName: '',
            employees: [{ name: '', active: false, key: randomId() }],
        },
    });

    const nextStep = () => setActive((current: number) => (current < 4 ? current + 1 : current));
    const prevStep = () => setActive((current: number) => (current > 0 ? current - 1 : current));
    const formatDate = (isoString: string): string => {
        const date = new Date(isoString);
            return date.toISOString().split('T')[0]; // Extracts 'YYYY-MM-DD' from ISO string
        };

    const handleSubmit = async () => {

        const formData = {
            username:localStorage.getItem('username'),
            title: socialForm.values.title,
            category: socialForm.values.category,
            targetAmount: target === 'deadline' ? socialForm.values.targetAmount : undefined,
            deadlineDate: target === 'deadline' && deadlineDate ? formatDate(String(deadlineDate)) : undefined,
            donationType,
            minimumCheck,
            interest: 0,
            // firstName: socialForm.values.firstName,
            // lastName: socialForm.values.lastName,
            // profilePicture: socialForm.values.profilePicture,
            // socialLinks: socialForm.values.employees.map(e => ({
            //     name: e.name,
            //     active: e.active
            // })),
            bkashNumber,
            nagadNumber,
            rocketNumber,
            story: editor?.getHTML(),
        };
        console.log('formData:', formData);

        try {
            const authToken = localStorage.getItem('authToken');

            if (!authToken) {
              console.error('No token found, please log in again.');
              alert('Please log in again.');
              //setIsSubmitting(false); // Re-enable the button on failur
              return; // Stop if there's no token
            }
          
            const response = await fetch('http://localhost:3000/api/loans/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${authToken}` 
                  },
               body: JSON.stringify(formData),
            });
            console.log("here i am");
            if (response.status === 401 || response.status === 403) {
                alert('Your session has expired or is invalid. Please log in again.');
                localStorage.removeItem('authToken'); // Clear token if invalid
                navigate('/login');
                //setIsSubmitting(false); // Re-enable the button on failure
                return; // Stop further execution
              }
              console.log("not createed loan");
            console.log(response);
          
              if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || 'Failed to create loan.');
              }
              const data = await response.json();
              console.log(data);
             if(data.loan._id) {
                navigate(`/loans/${data.loan._id}`);
            }
                } catch (error) {
                   console.error('Error:', error);
        }  //finally {
            //setIsSubmitting(false); // Re-enable the button after submission
        //}
    };

    const socialFields = socialForm.values.employees.map((item, index) => (
        <Group key={item.key} mt="xs">
            <Select
                aria-label="social"
                data={[
                    { title: 'Facebook', icon: IconBrandFacebook },
                    { title: 'Whatsapp', icon: IconBrandWhatsapp },
                    { title: 'LinkedIn', icon: IconBrandLinkedin },
                    { title: 'Twitter', icon: IconBrandTwitter },
                    { title: 'Youtube', icon: IconBrandYoutube },
                    { title: 'Other links', icon: IconLink },
                ].map(c => ({ value: c.title, label: c.title, ...c }))}
                itemComponent={SocialSelectItem}
            />
            <TextInput
                placeholder="https://"
                sx={{ flex: 1 }}
                {...socialForm.getInputProps(`employees.${index}.name`)}
            />
            <ActionIcon color="red" onClick={() => socialForm.removeListItem('employees', index)}>
                <IconTrash size="1rem" />
            </ActionIcon>
        </Group>
    ));

    const titleProps: TitleProps = {
        size: 24,
        mb: "md"
    };

    const subTitleProps: TitleProps = {
        size: 18,
        mb: "sm"
    };

    const paperProps: PaperProps = {
        p: "md",
        withBorder: false,
        shadow: 'sm',
        mb: "md",
        sx: { backgroundColor: theme.white }
    };

    return (
        <>
            <Helmet>
                <title>Create Loan</title>
            </Helmet>
            <Box>
                <Container my={36}>
                    <Title mb="xl" align="center">Create your Loan</Title>
                    <Stepper active={active} onStepClick={setActive} breakpoint="sm">
                        <Stepper.Step
                            label="Get started"
                            description="Set essential loan details such as 
                            loan title,target and interest amount"
                        >
                            <Title {...titleProps}>Loan information</Title>
                            <Paper {...paperProps}>
                                <SimpleGrid cols={2} breakpoints={[{ maxWidth: 'sm', cols: 1 }]}>
                                    <TextInput label="Title" {...socialForm.getInputProps('title')} />
                                    <CategoryLoan value={socialForm.getInputProps('category').value} onChange={socialForm.getInputProps('category').onChange} />
                                    </SimpleGrid>
                            </Paper>
                            <Paper {...paperProps}>
                                <Stack spacing="sm">
                                    <Title {...subTitleProps}>Loan Details</Title>
                                    <Paper {...paperProps}>
                                        {target === 'deadline' ?
                                            <Stack spacing="xs">
                                                <DateInput
                                                    value={deadlineDate}
                                                    onChange={setDeadlineDate}
                                                    label="Deadline"
                                                    placeholder="Date input"
                                                    icon={<IconCalendar size={18} />}
                                                />
                                                <NumberInput
                                                    label="Target amount"
                                                    icon={<IconCurrencyTaka size={18} />}
                                                    {...socialForm.getInputProps('targetAmount')}
                                                />
                                                {/* <Checkbox
                                                    label="Allow your fundraiser to be funded over the needed amount?"
                                                    {...socialForm.getInputProps('allowOverAmount', { type: 'checkbox' })}
                                                /> */}
                                            </Stack> :
                                            <Stack spacing="xs">
                                                <Text size="sm">Ongoing (no deadline) Loan?</Text>
                                                <Text size="sm">This should be used if you are collecting money on a
                                                    regular basis.</Text>
                                                <Checkbox
                                                    checked={minimumCheck}
                                                    onChange={(event) => setMinimumCheck(event.currentTarget.checked)}
                                                    label="Select this if you would like to set a specific a minimum financial target"
                                                />
                                                {minimumCheck &&
                                                    <NumberInput
                                                        label="Target amount"
                                                        icon={<IconCurrencyTaka size={18} />}
                                                        {...socialForm.getInputProps('minimumTargetAmount')}
                                                    />}
                                            </Stack>}
                                    </Paper>
                                </Stack>
                            </Paper>
                            <Paper {...paperProps}>
                                <Title {...subTitleProps}>Return type</Title>
                                <SegmentedControl
                                    size="md"
                                    value={donationType}
                                    onChange={setDonationType}
                                    data={[
                                        { label: '1 Time', value: '1 Time' },
                                        { label: 'Monthly', value: 'Monthly' },
                                        // { label: 'Lender wish', value: 'Lender wish' },
                                    ]}
                                    mb="sm"
                                />
                                {/* <NumberInput label="Interest(%)" {...socialForm.getInputProps('interest')} /> */}
                            </Paper>
                        </Stepper.Step>
                        <Stepper.Step
                            label="Loan Purpose"
                            description={<>
                            Tell us why you need this loan! 
                            Add images so that lenders can trust you.
                        </>}>
                            <Title {...titleProps}>
                                Your Loan story
                            </Title>
                            <Paper {...paperProps}>
                                <Stack spacing="sm">
                                    <Text size="sm">Explain why you&apos;re asking for money, what the loan will be used
                                        for, and
                                        how much you value the support</Text>
                                    <RichTextEditor editor={editor}>
                                        <RichTextEditor.Toolbar sticky stickyOffset={60}>
                                            <RichTextEditor.ControlsGroup>
                                                <RichTextEditor.Bold />
                                                <RichTextEditor.Italic />
                                                <RichTextEditor.Underline />
                                                <RichTextEditor.Strikethrough />
                                                <RichTextEditor.ClearFormatting />
                                                <RichTextEditor.Highlight />
                                                <RichTextEditor.Code />
                                            </RichTextEditor.ControlsGroup>

                                            <RichTextEditor.ControlsGroup>
                                                <RichTextEditor.H1 />
                                                <RichTextEditor.H2 />
                                                <RichTextEditor.H3 />
                                                <RichTextEditor.H4 />
                                            </RichTextEditor.ControlsGroup>

                                            <RichTextEditor.ControlsGroup>
                                                <RichTextEditor.Blockquote />
                                                <RichTextEditor.Hr />
                                                <RichTextEditor.BulletList />
                                                <RichTextEditor.OrderedList />
                                                <RichTextEditor.Subscript />
                                                <RichTextEditor.Superscript />
                                            </RichTextEditor.ControlsGroup>

                                            <RichTextEditor.ControlsGroup>
                                                <RichTextEditor.Link />
                                                <RichTextEditor.Unlink />
                                            </RichTextEditor.ControlsGroup>

                                            <RichTextEditor.ControlsGroup>
                                                <RichTextEditor.AlignLeft />
                                                <RichTextEditor.AlignCenter />
                                                <RichTextEditor.AlignJustify />
                                                <RichTextEditor.AlignRight />
                                            </RichTextEditor.ControlsGroup>
                                        </RichTextEditor.Toolbar>

                                        <RichTextEditor.Content />
                                    </RichTextEditor>
                                    <FileDropzone
                                        label="Upload campaign photos"
                                        description="You can select and upload one image in one go"/>
                                </Stack>
                            </Paper>
                        </Stepper.Step>
                        {/* <Stepper.Step label="Payment methods" description="Get full access">
                            <Title {...titleProps}>Loan Payment Methods</Title>
                            <Paper {...paperProps}>
                                <Stack spacing="sm">
                                    <Title {...subTitleProps}>Enable payment processors for your Loan
                                        page</Title>
                                    <Alert icon={<IconCurrencyTaka size={18} />} color="blue">You can enable Payment method listed below for Taking Payment </Alert>
                                    <Text size="sm">Available payment methods</Text>
                                    <Group>
                                        <Button variant="light" leftIcon={<IconBrandPaypal size={18} />}>Bkash Number</Button>
                                        <TextInput 
                                            placeholder="Enter Bkash Number"
                                            value={bkashNumber}
                                            onChange={(e) => setBkashNumber(e.currentTarget.value)}
                                        />
                                        <Button variant="light" leftIcon={<IconBrandPaypal size={18} />}>Nagad Number</Button>
                                        <TextInput 
                                            placeholder="Enter Nagad Number"
                                            value={nagadNumber}
                                            onChange={(e) => setNagadNumber(e.currentTarget.value)}
                                        />
                                        <Button variant="light" leftIcon={<IconBrandPaypal size={18} />}>Rocket Number</Button>
                                        <TextInput 
                                            placeholder="Enter Rocket Number"
                                            value={rocketNumber}
                                            onChange={(e) => setRocketNumber(e.currentTarget.value)}
                                        />
                                    </Group>
                                </Stack>
                            </Paper>
                        </Stepper.Step> */}
                        <Stepper.Completed>
                            <Title {...titleProps} align="center" my="xl">Completed, take a seat while we finish setting
                                up things for you</Title>
                        </Stepper.Completed>
                    </Stepper>

                    <Group position="center" mt="xl">
                        <Button
                            variant="default"
                            onClick={prevStep}
                            leftIcon={<IconChevronLeft size={18} />}
                        >
                            Back
                        </Button>
                        {active < 3 ?
                            <Button onClick={nextStep} leftIcon={<IconChevronRight size={18} />}>Next step</Button> :
                            // <Button onClick={handleSubmit} component="a" href="/dashboard" leftIcon={<IconCheck size={18} />}>Launch
                             <Button onClick={handleSubmit} leftIcon={<IconCheck size={18} />}>Launch
                            Loan</Button>
                        }
                    </Group>
                </Container>
            </Box>
        </>
    );
};

export default CreateLoanPage;
