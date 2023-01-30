from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import Iterable

from ofrak.core.binary import GenericBinary
from ofrak.resource import Resource
from ofrak_type.range import Range
from ofrak.component.unpacker import Unpacker, UnpackerError
from ofrak.service.resource_service_i import ResourceFilter
from ofrak.model.resource_model import ResourceAttributes
from ofrak.core.flash import (
    FlashLogicalDataResource,
)

#####################
#     RESOURCES     #
#####################
@dataclass
class ScrambledFlashResource(GenericBinary):
    """
    Resource that has encoding to randomize contents
    Generally encoding is XOR
    """

#####################
#    ATTRIBUTES     #
#####################
class FlashEncodingAlgorithm(ABC):
    """
    Abstract implementation for custom encoding/decoding algorithms 
    """
    @abstractmethod
    def encode(self, payload: bytes) -> bytes:
        raise NotImplementedError()

    @abstractmethod
    def decode(self, payload: bytes) -> bytes:
        raise NotImplementedError()

@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class FlashEncodingAttributes(ResourceAttributes):
    """
    Provide parameters for the custom `FlashEncodingAlgorithm` 
    """
    encoding_algo: FlashEncodingAlgorithm
    encoding_key: Iterable[bytes]
    encoding_length: int

@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class ScrambledFlashAttributes(ResourceAttributes):
    """
    Attributes describing how to scramble/unscramble flash data
    Allows for list to support different algorithms and key
    """
    encoding_pattern: Iterable[FlashEncodingAttributes]


#####################
#    UNPACKERS     #
#####################
class ScrambledFlashResourceUnpacker(Unpacker[None]):
    """
    Unpacks a `ScrambledFlashResource` using a custom decoding algorithm
    Needs `ScrambledFlashAttributes` to supply parameters
    """

    targets = (ScrambledFlashResource,)
    children = (FlashLogicalDataResource,)

    async def unpack(self, resource: Resource, config=None):
        try:
            scrambled_attr = resource.get_attributes(ScrambledFlashAttributes)
        except NotFoundError:
            raise UnpackerError("Tried unpacking ScrambledFlashResource with ScrambledFlashAttributes")

        data = await resource.get_data()
        data_len = len(data)

        unpacked_data = b''
        cur_index = 0
        while cur_index < data_len:
            # Loop through every pattern in the data until out of data
            for pattern in scrambled_attr.encoding_pattern:
                encoding_algo = pattern.encoding_algo()
                pattern_len = pattern.encoding_length
                if pattern_len == 0:
                    payload = data[cur_index:]
                else:
                    payload = data[cur_index:cur_index+pattern_len]
                key = pattern.encoding_key
                unpacked_data += encoding_algo.decode(payload, key)
                
                if pattern_len == 0:
                    cur_index += len(payload)
                cur_index += pattern_len 

        return await resource.create_child(
            tags=(FlashLogicalDataResource,),
            data=unpacked_data,
            attributes=[scrambled_attr,],
        )
