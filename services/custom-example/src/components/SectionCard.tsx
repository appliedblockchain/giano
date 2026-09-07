import { Card } from '@chakra-ui/react';
import type { ReactNode } from 'react';

type SectionCardProps = {
  title: ReactNode;
  description?: string;
  children: ReactNode;
};

/** Frosted card used for every panel, matching the demo's glassy look over the gradient. */
export function SectionCard({ title, description, children }: SectionCardProps) {
  return (
    <Card.Root
      bg="rgba(255, 255, 255, 0.95)"
      backdropFilter="blur(10px)"
      borderWidth="1px"
      borderColor="rgba(255, 255, 255, 0.4)"
      shadow="lg"
      rounded="xl"
    >
      <Card.Header>
        <Card.Title fontSize="lg">{title}</Card.Title>
        {description && <Card.Description>{description}</Card.Description>}
      </Card.Header>
      <Card.Body pt="0">{children}</Card.Body>
    </Card.Root>
  );
}
