#!/usr/bin/env python3

"""
Listen and event mechanism for Amazon Dash Buttons.
"""

__author__ = 'Matt Deacalion Stevens'
__version__ = '0.0.1'

import socket
import struct

sock = socket.socket(
    socket.AF_PACKET,
    socket.SOCK_RAW,
    socket.htons(0x0806),  # 0806 == ARP
)


class DashButton:
    """
    An Amazon Dash Button. Subclass this to add your own buttons.
    """
    def __init__(self, name, mac_address):
        """
        Initialise with a name and MAC address.
        """
        self.name = name
        self.mac_address = mac_address.replace(':', '').lower()
        self.triggered = 0

    def action(self):
        """
        This is run every time the button is pressed.
        """
        self.triggered += 1


class GilletteButton(DashButton):
    """
    An example subclassed button with a custom action.
    """
    def action(self):
        """
        Subclassed to tell the user how many times the button has
        been pressed.
        """
        super().action()

        print('Razors needed! Triggered by "{}"'.format(self.name))
        print('Pushed {} time{}'.format(
            self.triggered,
            's'[self.triggered == 1:]),
        )


class Packet:
    """
    An Ethernet packet.
    """
    def __init__(self, data):
        """
        Initialise this class with a message (likely from `recv`).
        """
        # The headers we intend to extract from the packet. We only
        # extract the information needed to determine if it's an ARP
        # request and if it's coming from one of our buttons.
        names = ['destination', 'source', 'type', 'opcode']

        # Create a dictionary from the ethernet frame.
        self.data = dict(zip(
            names,
            struct.unpack('>6s6s2s6x2s38x', data),
        ))

        # Convert the hex byte values in the dictionary to ASCII
        self.data.update({
            k: ''.join(format(_, '02x') for _ in v)
            for k, v in self.data.items()
        })

    @property
    def is_arp_request(self):
        """
        Returns `True` if this packet is a `who-has` ARP request.
        """
        # `who-has` ARP requests are always broadcast packets, so the
        # physical destination will be `ff:ff:ff:ff:ff:ff`
        if self.data['destination'] != 'ffffffffffff':
            return False

        # The header type for ARP packets is `0x0806`
        if self.data['type'] != '0806':
            return False

        # An ARP packet can be either `who-has` or `tell`, we're only
        # interested in the Dash Button asking `who-has`
        if self.data['opcode'] != '0001':
            return False

        return True


def main():
    # Our buttons
    buttons = [
        GilletteButton('Gillette button #2', 'AC:63:BE:B2:A2:05'),
    ]

    while True:
        packet = Packet(sock.recv(65536))

        if packet.is_arp_request:
            for button in buttons:
                if packet.data['source'] == button.mac_address:
                    button.action()


if __name__ == '__main__':
    main()
