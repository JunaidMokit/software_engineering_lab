import {Helmet} from "react-helmet";
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
import {Link, RichTextEditor} from '@mantine/tiptap';
import {useEditor} from '@tiptap/react';
import Highlight from '@tiptap/extension-highlight';
import StarterKit from '@tiptap/starter-kit';
import Underline from '@tiptap/extension-underline';
import TextAlign from '@tiptap/extension-text-align';
import Superscript from '@tiptap/extension-superscript';
import SubScript from '@tiptap/extension-subscript';
import React, {forwardRef, useState} from "react";
import {DateInput} from "@mantine/dates";

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
    IconCurrency,
    IconCurrencyTaka,
    IconInfoCircleFilled,
    IconLink,
    IconMail,
    IconPlus,
    IconTrash
} from "@tabler/icons-react";
import {CategorySelect, CountrySelect, CurrencySelect, FileDropzone} from "../components";
import {randomId} from "@mantine/hooks";
import {useForm} from "@mantine/form";
import {useNavigate} from "react-router-dom";

interface ISocialProps {
    icon: React.FC<any>;
    title: React.ReactNode;
}

const SocialSelectItem = forwardRef<HTMLDivElement, ISocialProps>(
    ({title, icon: Icon, ...others}: ISocialProps, ref) => (
        <div ref={ref} {...others}>
            <Group noWrap>
                <Icon size={18} stroke={1.5}/>
                <Text size="sm" transform="capitalize">{title}</Text>
            </Group>
        </div>
    )
);

const CreateCampaignPage = () => {
    const navigate=useNavigate();
    const theme = useMantineTheme();
    const [active, setActive] = useState(0);
    const [target, setTarget] = useState('deadline');
    const [amount, setAmount] = React.useState<number | ''>(0);
    const [deadlineDate, setDeadlineDate] = useState<Date | null>(null);
    const [donationType, setDonationType] = useState('any');
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
            TextAlign.configure({types: ['heading', 'paragraph']}), 
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
            profilePicture: '',
            employees: [{ name: '', active: false, key: randomId() }],
        },    });

    const nextStep = () => setActive((current: number) => (current < 4 ? current + 1 : current));
    const prevStep = () => setActive((current: number) => (current > 0 ? current - 1 : current));

    const titleProps: TitleProps = {
        size: 24,
        mb: "md"
    }

    const subTitleProps: TitleProps = {
        size: 18,
        mb: "sm"
    }

    const paperProps: PaperProps = {
        p: "md",
        withBorder: false,
        shadow: 'sm',
        mb: "md",
        sx: {backgroundColor: theme.white}
    }
    const [image, setImage] = useState();

    const handleImageDrop = (file) => {
        console.log(file);
        setImage(file[0]);
    };
    const handleSubmit = async () => {
        const campaignData = new FormData();
        campaignData.append('title', socialForm.values.title);
        campaignData.append('category', socialForm.values.category);
        campaignData.append('target', target);
        campaignData.append('deadlineDate', deadlineDate?.toISOString() || '');
        campaignData.append('donationType', donationType);
        campaignData.append('amount', amount);
        campaignData.append('bkashNumber', bkashNumber);
        campaignData.append('nagadNumber', nagadNumber);
        campaignData.append('rocketNumber', rocketNumber);
        campaignData.append('username', localStorage.getItem('username') || '');
        campaignData.append('story', editor?.getHTML() || '');
        console.log("data", campaignData);
    
        if (image) {
                campaignData.append('image', image); 
        }
    
        try {
            const response = await fetch('http://localhost:3000/api/campaign/create', {
                method: 'POST',
                body: campaignData,
            });
    
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
    
            const result = await response.json();
            navigate('/campaigns/' + result._id);
        } catch (error) {
            console.error('Error creating campaign:', error);
        }
    };
    

    return (
        <>
     <Helmet>
                <title>Create campaign</title>
            </Helmet>
            <Box>
                <Container my={36}>
                    <Title mb="xl" align="center">Create your campaign</Title>
                    <Stepper active={active} onStepClick={setActive} breakpoint="sm">
                        <Stepper.Step
                            label="Get started"
                            description="Set essential campaign details such as campaign title, target and currency"
                        >
                            <Title {...titleProps}>Campaign information</Title>
                            <Paper {...paperProps}>
                                <SimpleGrid cols={2} breakpoints={[{maxWidth: 'sm', cols: 1}]}>
                                <TextInput label="Title" value={socialForm.getInputProps('title').value} onChange={socialForm.getInputProps('title').onChange} />
                                <CategorySelect value={socialForm.getInputProps('category').value} onChange={socialForm.getInputProps('category').onChange} />
                                </SimpleGrid>
                            </Paper>
                            <Paper {...paperProps}>
                                <Stack spacing="sm">
                                    <Title {...subTitleProps}>Donation information</Title>
                                    <Radio.Group
                                        label="What kind of Campaign would you like to create?"
                                        value={target}
                                        onChange={setTarget}
                                    >
                                        <Group mt="xs">
                                            <Radio value="deadline" label="Campaign with a specific end date?"/>
                                            <Radio value="no-deadline" label="Ongoing (no deadline) campaign?"/>
                                        </Group>
                                    </Radio.Group>
                                    <Paper {...paperProps}>
                                        {target === 'deadline' ?
                                            <Stack spacing="xs">
                                                <Text size="sm">Campaign with a specific end date?</Text>
                                                <Text size="sm">This creates urgency and should always be used when money is needed before a certain time.</Text>
                                                <DateInput
                                                    value={deadlineDate}
                                                    onChange={setDeadlineDate}
                                                    label="Deadline"
                                                    placeholder="Date input"
                                                    icon={<IconCalendar size={18}/>}
                                                />
                                                {/* <NumberInput
                                                    label="Target amount"
                                                    value={amount}
                                                    onChange={(value) => setAmount(value)}
                                                    icon={<IconCurrencyDollar size={18}/>}/>
                                                {/* <Checkbox
                                                    label="Allow your fundraiser to be funded over the needed amount?"/> */}
                                            </Stack> :
                                            <Stack spacing="xs">
                                                <Text size="sm">Ongoing (no deadline) campaign?</Text>
                                                <Text size="sm">This should be used if you are collecting money on a regular basis.</Text>                                                
                                            </Stack>}
                                    </Paper>
                                </Stack>
                            </Paper>
                            <Paper {...paperProps}>
                                <Title {...subTitleProps}>Donation type</Title>
                                <SegmentedControl
                                    size="md"
                                    value={donationType}
                                    onChange={setDonationType}
                                    data={[
                                        {label: 'Any (popular option)', value: 'any'},
                                        {label: 'Minimum', value: 'minimum'},
                                        {label: 'Fixed', value: 'fixed'},
                                    ]}
                                    mb="sm"
                                />
                                {donationType === 'minimum' ?
                                    <NumberInput value={amount}
                                    onChange={setAmount} label="Minimum amount(s)"/> :
                                    <NumberInput value={amount}
                                    onChange={setAmount} label="Fixed amount(s)"/>}
                            </Paper>
                            {/* <Paper {...paperProps}>
                                <Stack spacing="sm">
                                    <Title {...subTitleProps}>Fund & Registration details</Title>
                                    <Text size="sm">*Name of the person receiving funds. For organizations, the legal representative name (this can be amended later).</Text>
                                    <SimpleGrid cols={2} breakpoints={[{maxWidth: 'sm', cols: 1}]}>
                                        <TextInput label="Organization or Person Name"/>
                                    </SimpleGrid>
                                    <FileDropzone
                                        label="Upload DP picture"
                                        description="This picture will be shown next to your name"
                                    />
                                    <Checkbox label={
                                        <>
                                            I agree to the CrowdUp{' '}
                                            <Anchor href="#" target="_blank">
                                                terms and conditions & privacy policy
                                            </Anchor>
                                        </>
                                    }/>
                                </Stack>
                            </Paper> */}
                        </Stepper.Step>
                        <Stepper.Step
                            label="Campaign story"
                            description="Tell your story! Add your description, images and more">
                            <Title {...titleProps}>
                                Your campaign story
                            </Title>
                            <Paper {...paperProps}>
                                <Stack spacing="sm">
                                    <Text size="sm">Explain why you’re raising money, what the funds will be used for, and how much you value the support</Text>
                                    <RichTextEditor editor={editor}>
                                        <RichTextEditor.Toolbar sticky stickyOffset={60}>
                                            <RichTextEditor.ControlsGroup>
                                                <RichTextEditor.Bold/>
                                                <RichTextEditor.Italic/>
                                                <RichTextEditor.Underline/>
                                                <RichTextEditor.Strikethrough/>
                                                <RichTextEditor.ClearFormatting/>
                                                <RichTextEditor.Highlight/>
                                                <RichTextEditor.Code/>
                                            </RichTextEditor.ControlsGroup>

                                            <RichTextEditor.ControlsGroup>
                                                <RichTextEditor.H1/>
                                                <RichTextEditor.H2/>
                                                <RichTextEditor.H3/>
                                                <RichTextEditor.H4/>
                                            </RichTextEditor.ControlsGroup>

                                            <RichTextEditor.ControlsGroup>
                                                <RichTextEditor.Blockquote/>
                                                <RichTextEditor.Hr/>
                                                <RichTextEditor.BulletList/>
                                                <RichTextEditor.OrderedList/>
                                                <RichTextEditor.Subscript/>
                                                <RichTextEditor.Superscript/>
                                            </RichTextEditor.ControlsGroup>

                                            <RichTextEditor.ControlsGroup>
                                                <RichTextEditor.Link/>
                                                <RichTextEditor.Unlink/>
                                            </RichTextEditor.ControlsGroup>

                                            <RichTextEditor.ControlsGroup>
                                                <RichTextEditor.AlignLeft/>
                                                <RichTextEditor.AlignCenter/>
                                                <RichTextEditor.AlignJustify/>
                                                <RichTextEditor.AlignRight/>
                                            </RichTextEditor.ControlsGroup>
                                        </RichTextEditor.Toolbar>

                                        <RichTextEditor.Content/>
                                    </RichTextEditor>
                                    <FileDropzone
                                        label="Upload campaign photos"
                                        description="You can select and upload several in one go"
                                        onDrop={handleImageDrop} // Call the handler on file drop
                                    />
                                </Stack>
                            </Paper>
                        </Stepper.Step>
                        {/* <Stepper.Step label="Payment methods" description="Get full access">
                            <Title {...titleProps}>Campaign Payment Methods</Title>
                            <Paper {...paperProps}>
                                <Stack spacing="sm">
                                    <Title {...subTitleProps}>Enable payment processors for your campaign page</Title>
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
                            <Title {...titleProps} align="center" my="xl">Completed, take a seat while we finish setting up things for you</Title>
                        </Stepper.Completed>
                    </Stepper>
                    <Group position="center" mt="xl">
                        <Button
                            variant="default"
                            onClick={prevStep}
                            leftIcon={<IconChevronLeft size={18}/>}
                            >
                            Back
                        </Button>
                        {active < 4 ?
                            <Button onClick={nextStep} leftIcon={<IconChevronRight size={18}/>}>Next step</Button> :
                            <Button onClick={handleSubmit} leftIcon={<IconCheck size={18}/>}>Launch campaign</Button>
                        }
                    </Group>
                </Container>
            </Box>
        </>
    );
};

export default CreateCampaignPage;
