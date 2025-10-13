import React, { forwardRef } from 'react';
import { Group, Select, Text } from '@mantine/core';
import {
    IconAugmentedReality,
    IconCat,
    IconClipboardHeart,
    IconDeviceTv,
    IconFireHydrant,
    IconHeartHandshake,
    IconLeaf,
    IconReportMoney,
    IconSos
} from '@tabler/icons-react';

// Define the shape of the category data
interface Category {
    icon: React.ComponentType<{ size: number }>;
    title: string;
}

// Mock data for categories
const mockdata: Category[] = [
    { icon: IconClipboardHeart, title: 'Medical' },
    { icon: IconSos, title: 'Emergency' },
    { icon: IconLeaf, title: 'Environment' },
    { icon: IconHeartHandshake, title: 'Nonprofit' },
    { icon: IconReportMoney, title: 'Financial emergency' },
    { icon: IconCat, title: 'Animals' },
    { icon: IconFireHydrant, title: 'Crisis Relief' },
    { icon: IconAugmentedReality, title: 'Technology' },
    { icon: IconDeviceTv, title: 'Film & Videos' },
];

// Define props for the CategorySelectItem component
interface CategorySelectItemProps {
    title: string;
    icon: React.ComponentType<{ size: number }>;
}

const CategorySelectItem = forwardRef<HTMLDivElement, CategorySelectItemProps>(
    ({ title, icon: Icon, ...others }: CategorySelectItemProps, ref) => (
        <div ref={ref} {...others}>
            <Group noWrap>
                <Icon size={18} />
                <div>
                    <Text size="sm">{title}</Text>
                </div>
            </Group>
        </div>
    )
);

interface CategorySelectProps {
    value: string | null;
    onChange: (value: string | null) => void;
}

const CategorySelect: React.FC<CategorySelectProps> = ({ value, onChange }) => {
    const handleChange = (newValue: string | null) => {
        // Ensure newValue is not null and handle it
        onChange(newValue);
    };

    return (
        <Select
            label="Category"
            itemComponent={CategorySelectItem}
            data={mockdata.map(c => ({ value: c.title, label: c.title, ...c }))}
            searchable
            clearable
            maxDropdownHeight={300}
            nothingFound="Nothing found"
            value={value}
            onChange={handleChange}
            filter={(value, item) =>
                item?.title?.toLowerCase().includes(value?.toLowerCase().trim())
            }
        />
    );
};

export default CategorySelect;

