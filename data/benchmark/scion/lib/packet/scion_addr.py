# Copyright 2014 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`scion_addr` --- SCION host address specifications
=======================================================
"""
from collections import defaultdict, deque
from typing import Deque, List, Tuple, cast, Dict, Any

# Stdlib
import struct
import copy
import heapq
import logging
import math
# from collections import deque

# External
import yaml

# SCION
from ..errors import SCIONIndexError, SCIONParseError
from .packet_base import Serializable
from .host_addr import (
    HostAddrBase,
    haddr_get_type,
)
from ..util import Raw, SCIONTime, load_yaml_file
from .opaque_field import HopOpaqueField



class ISD_AS():
    """
    Class for representing isd-as pair.
    """
    _isd:int = 0
    _as:int = 0
    NAME:str = "ISD_AS"
    LEN:int = 4

    def __init__(self, raw=None):
        self._isd = 0
        self._as = 0
        # super().__init__(raw)

    def _parse(self, raw):  # pragma: no cover
        if isinstance(raw, bytes):
            self._parse_bytes(raw)
        elif isinstance(raw, int):
            self._parse_int(raw)
        else:
            self._parse_str(raw)

    def _parse_bytes(self, raw):
        """
        :param bytes raw:
            a byte string containing ISD ID, AS ID. ISD and AS are respectively
            represented as 12 and 20 most significant bits.
        """
        data = Raw(raw, self.NAME, self.LEN)
        isd_as = cast(int, struct.unpack("!I", data.pop())[0])
        self._parse_int(isd_as)

    def _parse_str(self, raw):
        """
        :param str raw: a string of the format "isd-as".
        """
        isdas_ = raw.split("-", 1)
        isd = isdas_[0]
        as_ = isdas_[1]
        try:
            self._isd = int(isd)
        except ValueError:
            raise SCIONParseError("Unable to parse ISD from string: %s", raw)
        try:
            self._as = int(as_)
        except ValueError:
            raise SCIONParseError("Unable to parse AS from string: %s", raw)

    def _parse_int(self, raw):
        """
        :param int raw: a 32bit int containing the ISD ID in the 12 MSBs and the
            AS ID in the remaining 20 bits.
        """
        self._isd = raw >> 20
        self._as = raw & 0x000fffff

    @staticmethod  # CHANGE: Turned classmethod into staticmethod
    def from_values(isd, as_):  # pragma: no cover
        inst = ISD_AS()
        inst._isd = isd
        inst._as = as_
        return inst

    def pack(self):
        return struct.pack("!I", self.int())

    def int(self):
        isd_as = self._isd << 20
        isd_as |= self._as & 0x000fffff
        return isd_as

    def any_as(self):
        return ISD_AS.from_values(self._isd, 0)  # CHANGE: Changed call target from self to class

    def params(self, name="first"):  # pragma: no cover
        """Provides parameters for querying PathSegmentDB"""
        if self._as == 0:
            return {"%s_isd" % name: self._isd}
        else:
            return {"%s_ia" % name: self}

    def __eq__(self, other):  # pragma: no cover
        return self._isd == other._isd and self._as == other._as

    def __getitem__(self, idx):  # pragma: no cover
        if idx == 0:
            return self._isd
        elif idx == 1:
            return self._as
        else:
            raise SCIONIndexError("Invalid index used on %s object: %s" % (
                                  (self.NAME, idx)))

    def __int__(self):
        return self.int()

    def __iter__(self):  # CHANGE: changed generator to return list
        return [self._isd, self._as]

    def __str__(self):
        return "%s-%s" % (self._isd, self._as)

    def __repr__(self):
        return "ISD_AS(isd=%s, as=%s)" % (self._isd, self._as)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __hash__(self):  # pragma: no cover
        return hash(str(self))


class SCIONAddr(object):
    """
    Class for complete SCION addresses.

    :ivar ISD_AS isd_as: ISD-AS identifier.
    :ivar HostAddrBase host: host address.
    :ivar int addr_len: address length.
    """

    isd_as:ISD_AS = None
    host:HostAddrBase = None
    def __init__(self, addr_info = False):  # pragma: no cover
        """
        Initialize an instance of the class SCIONAddr.

        :param addr_info: Tuple of (addr_type, addr) for the host address
        """
        self.isd_as = None
        self.host = None
        if addr_info:
            self._parse(3, bytes(34))

    def _parse(self, addr_type, raw):
        """
        Parse a raw byte string.

        :param int addr_type: Host address type
        :param bytes raw: raw bytes.
        """
        haddr_type = haddr_get_type(addr_type)
        addr_len = ISD_AS.LEN + haddr_type.LEN
        data = Raw(raw, "SCIONAddr", addr_len, min_=True)
        self.isd_as = ISD_AS(data.pop(ISD_AS.LEN))
        self.host = haddr_type(data.pop(haddr_type.LEN))

    @staticmethod    # CHANGE: Turned classmethod into staticmethod
    def from_values(isd_as, host):  # pragma: no cover
        """
        Create an instance of the class SCIONAddr.

        :param ISD_AS isd_as: ISD-AS identifier.
        :param HostAddrBase host: host address
        """
        addr = SCIONAddr()
        addr.isd_as = isd_as
        addr.host = host
        return addr

    def pack(self):  # pragma: no cover
        """
        Pack the class variables into a byte string.

        :returns: a byte string containing ISD ID, AS ID, and host address.
        :rtype: bytes
        """
        return self.isd_as.pack() + self.host.pack()

    @staticmethod    # CHANGE: Turned classmethod into staticmethod
    def calc_len(type_):  # pragma: no cover
        class_ = haddr_get_type(type_)
        return ISD_AS.LEN + class_.LEN

    def __len__(self):  # pragma: no cover
        return len(self.isd_as) + len(self.host)

    def __eq__(self, other):  # pragma: no cover
        return (self.isd_as == other.isd_as and
                self.host == other.host)

    def __str__(self):
        """
        Return a string containing ISD-AS, and host address.
        """
        return "(%s (%s) %s)" % (self.isd_as, self.host.name(), self.host)




class PPCBMarking:
    """
    struct PCBMarking {
    inIA @0 :UInt32;  # Ingress (incl peer) ISD-AS
    inIF @1 :UInt64; # Interface ID on far end of ingress link
    inMTU @2 :UInt16;  # Ingress Link MTU
    outIA @3 :UInt32;  # Downstream ISD-AS
    outIF @4 :UInt64; # Interface ID on far end of egress link
    hof @5 :Data;
    }
    """
    inIA:int
    inIF:int
    inMTU:int
    outIA:int
    outIF:int
    def __init__(self) -> None:
        ...
        # self.inIA = 0
        # self.inIF = 0
        # self.inMTU = 0
        # self.outIA = 0
        # self.outIF = 0


class PCBMarking:
    p:PPCBMarking
    def __init__(self) -> None:
        self.p:PPCBMarking = PPCBMarking()

    def inIA(self) -> ISD_AS: ...

    def outIA(self) -> ISD_AS: ...

    def hof(self) -> HopOpaqueField:
        ...

class ASMarking:
    def isd_as(self) -> ISD_AS: ...
    def iter_pcbms(self, start: int=0) -> List[PCBMarking]:
        ...
    def pcbm(self, idx: int) -> PCBMarking:
        ...

class PathSegment:
    def short_desc(self) -> str: ...

    def iter_asms(self, start: int=0) -> List[ASMarking]:
        ...

    def get_n_peer_links(self) -> int:  ...

    def get_n_hops(self) -> int: ...

    def get_hops_hash(self, hex: bool = False) -> int: ...

    def get_timestamp(self) -> int: ...

    def get_expiration_time(self) -> int: ...





class PathPolicy(object):
    """Stores a path policy."""
    best_set_size:int
    candidates_set_size:int
    history_limit:int
    update_after_number:int
    update_after_time:int
    unwanted_ases:List[ISD_AS] = []
    property_ranges:Dict[str,Tuple[int,int]]
    property_weights:Dict[str, int]
    def __init__(self):  # pragma: no cover
        self.best_set_size = 5
        self.candidates_set_size = 20
        self.history_limit = 0
        self.update_after_number = 0
        self.update_after_time = 0
        self.unwanted_ases = []
        self.property_ranges = {}
        self.property_weights = {}



    def get_path_policy_dict(self):  # pragma: no cover
        return {
            'best_set_size': self.best_set_size,
            'candidates_set_size': self.candidates_set_size,
            'history_limit': self.history_limit,
            'update_after_number': self.update_after_number,
            'update_after_time': self.update_after_time,
            'unwanted_ases': self.unwanted_ases,
            'property_ranges': self.property_ranges,
            'property_weights': self.property_weights
        }
    def check_filters(self, pcb):
        """
        Runs some checks, including: unwanted ASes and min/max property values.

        :param pcb: beacon to analyze.
        :type pcb: :class:`PathSegment`
        :returns:
            True if any unwanted AS is present or a range is not respected.
        :rtype: bool
        """
        # assert isinstance(pcb, PathSegment)
        isd_as = self._check_unwanted_ases(pcb)
        if isd_as:
            logging.warning("PathStore: pcb discarded, unwanted AS(%s): %s",
                            isd_as, pcb.short_desc())
            return False
        reasons = self._check_property_ranges(pcb)
        if reasons:
            logging.info("PathStore: pcb discarded(%s): %s",
                         ", ".join(reasons), pcb.short_desc())
            return False
        ia = self._check_remote_ifid(pcb)
        if ia:
            logging.error("PathStore: pcb discarded, remote IFID of %s unknown",
                          ia)
            return False
        return True

    def _check_unwanted_ases(self, pcb):  # pragma: no cover
        """
        Checks whether any of the ASes in the path belong to the black list.

        :param pcb: beacon to analyze.
        :type pcb: :class:`PathSegment`
        """
        for asm in pcb.iter_asms():
            isd_as = asm.isd_as()
            if isd_as in self.unwanted_ases:
                return isd_as

    def _check_range(self, reasons, name, actual):  # CHANGE: Moved nested function out of
                                                    # method _check_property_ranges
        range_ = self.property_ranges[name]
        if not range_:
            return
        if (actual < range_[0] or actual > range_[1]):
            reasons.append("%s: %d <= %d <= %d" % (
                name, range_[0], actual, range_[1]))

    def _check_property_ranges(self, pcb):
        """
        Checks whether any of the path properties has a value outside the
        predefined min-max range.

        :param pcb: beacon to analyze.
        :type pcb: :class:`PathSegment`
        """

        reasons = []
        self._check_range(reasons, "PeerLinks", pcb.get_n_peer_links())  # CHANGE: Adapted
        self._check_range(reasons, "HopsLength", pcb.get_n_hops())       # calls to nested
        self._check_range(reasons, "DelayTime",                          # function.
                          int(SCIONTime.get_time()) - pcb.get_timestamp())
        self._check_range(reasons, "GuaranteedBandwidth", 10)
        self._check_range(reasons, "AvailableBandwidth", 10)
        self._check_range(reasons, "TotalBandwidth", 10)
        return reasons

    def _check_remote_ifid(self, pcb):
        """
        Checkes whether any PCB markings have unset remote IFID values for
        up/downstream ASes. This can happen during normal startup depending
        on the timing of PCB propagation vs IFID keep-alives, but should
        not happen once the infrastructure is settled.
        Remote IFID is only allowed to be 0 if the corresponding ISD-AS is
        0-0.
        """
        for asm in pcb.iter_asms():
            for pcbm in asm.iter_pcbms():
                
                if pcbm.inIA().int() != 0 and pcbm.p.inIF == 0:
                    return pcbm.inIA()
                if pcbm.outIA().int() != 0 and pcbm.p.outIF == 0:
                    return pcbm.outIA()
        return None
    @staticmethod   # CHANGE: Turned classmethod into staticmethod
    def from_file(policy_file):  # pragma: no cover
        """
        Create a PathPolicy instance from the file.

        :param str policy_file: path to the path policy file
        """
        return PathPolicy.from_dict(load_yaml_file(policy_file))

    @staticmethod   # CHANGE: Turned classmethod into staticmethod
    def from_dict(policy_dict):  # pragma: no cover
        """
        Create a PathPolicy instance from the dictionary.

        :param dict policy_dict: dictionary representation of path policy
        """
        path_policy = PathPolicy()
        path_policy.parse_dict(policy_dict)
        return path_policy

    def parse_dict(self, path_policy):
        """
        Parses the policies from the dictionary.

        :param dict path_policy: path policy.
        """
        self.best_set_size = cast(int, path_policy['BestSetSize'])  # CHANGE: added casts
        self.candidates_set_size = cast(int, path_policy['CandidatesSetSize'])
        self.history_limit = cast(int, path_policy['HistoryLimit'])
        self.update_after_number = cast(int, path_policy['UpdateAfterNumber'])
        self.update_after_time = cast(int, path_policy['UpdateAfterTime'])
        unwanted_ases = cast(str, path_policy['UnwantedASes']).split(',')
        for unwanted in unwanted_ases:
            self.unwanted_ases.append(ISD_AS(unwanted))
        property_ranges = cast(Dict[str, str], path_policy['PropertyRanges'])
        for key in property_ranges:
            property_range = property_ranges[key].split('-')
            property_range_temp = int(property_range[0]), int(property_range[1])  # CHANGE: Added local variable b/c variable changed type.
            self.property_ranges[key] = property_range_temp
        self.property_weights = cast(Dict[str, int], path_policy['PropertyWeights'])

    def __str__(self):
        path_policy_dict = self.get_path_policy_dict()
        path_policy_str = yaml.dump(path_policy_dict)
        return path_policy_str


    

    

    


class PathStoreRecord(object):
    """
    Path record that gets stored in the the PathStore.

    :cvar int DEFAULT_OFFSET:
        the amount of time subtracted from the current time when the path's
        initial last sent time is set.
    :ivar pcb: the PCB representing the record.
    :vartype pcb: :class:`lib.packet.pcb.PathSegment`
    :ivar bytes id: the path segment identifier stored in the record's PCB.
    :ivar float fidelity: the fidelity of the path record.
    :ivar float peer_links:
        the normalized number of peer links in the path segment.
    :ivar float hops_length: the normalized length of the path segment.
    :ivar float disjointness:
        the normalized disjointness of the path segment compared to the other
        paths in the PathStore.
    :ivar int last_sent_time:
        the Unix time at which the path segment was last sent.
    :ivar int last_seen_time:
        the Unix time at which the path segment was last seen.
    :ivar float delay_time:
        the normalized time in seconds between the PCB's creation and the time
        it was last seen by the path server.
    :ivar int expiration_time: the Unix time at which the path segment expires.
    :ivar int guaranteed_bandwidth: the path segment's guaranteed bandwidth.
    :ivar int available_bandwidth: the path segment's available bandwidth.
    :ivar int total_bandwidth: the path segment's total bandwidth.
    """
    DEFAULT_OFFSET:int = 3600 * 24 * 7  # 1 week
    id:int
    peer_links:int 
    hops_length:int 
    fidelity:float
    disjointness:int
    last_sent_time:int
    guaranteed_bandwidth:int
    available_bandwidth:int 
    total_bandwidth:int
    last_seen_time:int 
    pcb:PathSegment 
    delay_time:int
    expiration_time:int
    def __init__(self, pcb:PathSegment):
        """
        :param pcb: beacon to analyze.
        :type pcb: :class:`PathSegment`
        """
        # assert isinstance(pcb, PathSegment)
        self.id = pcb.get_hops_hash(hex=True)
        self.peer_links = pcb.get_n_peer_links()
        self.hops_length = pcb.get_n_hops()
        self.fidelity = 0
        self.disjointness = 0
        self.last_sent_time = int(SCIONTime.get_time()) - self.DEFAULT_OFFSET
        self.guaranteed_bandwidth = 0
        self.available_bandwidth = 0
        self.total_bandwidth = 0
        self.last_seen_time = -1    # CHANGE: Added attribute assignment to constructor
        self.update(pcb)

    def update(self, pcb):
        """
        Update a candidate entry from a recent PCB.
        """
        assert self.id == pcb.get_hops_hash(hex=True)
        now = int(SCIONTime.get_time())
        self.pcb:PathSegment = copy.deepcopy(pcb)
        self.delay_time:int = now - pcb.get_timestamp()
        self.last_seen_time:int = now
        self.expiration_time:int = pcb.get_expiration_time()

    def sending(self):  # pragma: no cover
        """
        Update last_sent_time to now.
        """
        self.last_sent_time = int(SCIONTime.get_time())

    def update_fidelity(self, path_policy):
        """
        Computes a path fidelity based on all path properties and considering
        the corresponding weights, which are stored in the path policy.

        :param dict path_policy: path policy.
        """
        self.fidelity = 0
        now = SCIONTime.get_time()
        self.fidelity += (path_policy.property_weights['PeerLinks'] *
                          self.peer_links)
        self.fidelity += (path_policy.property_weights['HopsLength'] /
                          self.hops_length)
        self.fidelity += (path_policy.property_weights['Disjointness'] *
                          self.disjointness)
        if now != 0:
            self.fidelity += (path_policy.property_weights['LastSentTime'] *
                              (now - self.last_sent_time) / now)
            self.fidelity += (path_policy.property_weights['LastSeenTime'] *
                              self.last_seen_time / now)
        self.fidelity += (path_policy.property_weights['DelayTime'] /
                          self.delay_time)
        self.fidelity += (path_policy.property_weights['ExpirationTime'] *
                          (self.expiration_time - now) / self.expiration_time)
        self.fidelity += (path_policy.property_weights['GuaranteedBandwidth'] *
                          self.guaranteed_bandwidth)
        self.fidelity += (path_policy.property_weights['AvailableBandwidth'] *
                          self.available_bandwidth)
        self.fidelity += (path_policy.property_weights['TotalBandwidth'] *
                          self.total_bandwidth)

    def __eq__(self, other):  # pragma: no cover
        if type(other) is not type(self):
            return False
        return self.id == other.id

    def __str__(self):
        return "PathStoreRecord: ID: %s Fidelity: %s" % (
            self.id, self.fidelity)


class PathStore(object):
    """Path Store class."""
    path_policy:PathPolicy
    candidates:List[PathStoreRecord]
    best_paths_history:Deque[int]
    disjointness:Dict[int, float]
    last_dj_update:int = 0
    def __init__(self, path_policy:PathPolicy):  # pragma: no cover
        """
        :param dict path_policy: path policy.
        """
        self.path_policy = path_policy
        self.candidates = []
        self.best_paths_history = deque(self.path_policy.history_limit)  # CHANGE: changed kw arg to normal arg
        self.disjointness = defaultdict(float)  # CHANGE: Added lambda
        self.last_dj_update = 0

    def add_segment(self, pcb):
        """
        Possibly add a new path to the candidates list.

        Attempt to add a path (which is an instance of PathSegment) to the set
        of candidate paths. If successfully added, the candidate path is stored
        in the PathStore as a PathStoreRecord.

        Before adding the path, the candidate PathSegment is first checked
        against the PathStore's filter criteria, listed in PathPolicy.  If the
        path's properties do not meet the filter criteria, the path is not
        added and the set of candidate paths remains unchanged.

        If the path passes the filter checks but is already in the candidate
        set (as determined by its identifier), then the path is not added to
        the candidate set. Instead, the delay and arrival times are updated in
        the existing record.

        If the path passes the filter checks and is not already in the
        candidate set, it is added to the list of candidate paths.  If upon
        adding the path, the candidate path set is too large (i.e., larger than
        candidates_set_size), the lowest-fidelity path is removed.

        :param pcb: The PCB representing the potential path.
        :type pcb: PathSegment
        """
        # assert isinstance(pcb, PathSegment)
        pcb_hash = pcb.get_hops_hash(hex=True)
        if not self.path_policy.check_filters(pcb):
            return
        for candidate in self.candidates:
            if candidate.id == pcb_hash:
                candidate.update(pcb)
                return
        record = PathStoreRecord(pcb)
        self.candidates.append(record)
        self._trim_candidates()

    def _trim_candidates(self):
        """
        Trims the set of candidate set if necessary.
        """
        if len(self.candidates) > self.path_policy.candidates_set_size:
            self._remove_expired_segments()
        if len(self.candidates) > self.path_policy.candidates_set_size:
            self._update_all_fidelity()
            self.candidates = sorted(self.candidates, lambda x: x.fidelity,
                                     True)[:-1]

    def _update_disjointness_db(self):
        """
        Update the disjointness database.

        Based on the current time, update the disjointness database keeping
        track of each path, AS, and interface previously sent.
        """
        now = SCIONTime.get_time()
        for k, v in self.disjointness.items():
            self.disjointness[k] = v * math.exp(self.last_dj_update - now)
        self.last_dj_update = now

    def _update_all_disjointness(self):
        """
        Update the disjointness of all path candidates.

        The disjointness of a candidate path is measured with respect to
        previously sent paths and is calculated as follows:

        Each time a path is sent, its ASes and AS-interface pairs are added to
        the (data structure). The exact path itself is also added to a list of
        previously sent paths.

        The disjointness is then calculated as the inverse of the sum of the
        following: the entire path, each AS on the path, and each AS-interface
        pair on the path.

        The disjointness is normalized by the highest-scoring path's
        disjointness.
        """
        self._update_disjointness_db()
        max_disjointness = 0.0
        test_asm = None
        test_isdas = None
        test_index = None
        for candidate in self.candidates:
            path_disjointness = self.disjointness[candidate.id]
            as_disjointness = 0.0
            if_disjointness = 0.0
            for asm in candidate.pcb.iter_asms():
                test_asm = asm
                test_isdas = asm.isd_as()
                test_index = asm.isd_as()[1]
                as_disjointness += self.disjointness[asm.isd_as()[1]]
                if_disjointness += self.disjointness[
                    asm.pcbm(0).hof().egress_if]
            candidate.disjointness = (path_disjointness + as_disjointness +
                                      if_disjointness)
            if candidate.disjointness > max_disjointness:
                max_disjointness = candidate.disjointness
        if max_disjointness > 0.0:
            for candidate in self.candidates:
                candidate.disjointness /= max_disjointness

    def _update_all_delay_time(self):
        """Update the delay time property of all path candidates."""
        max_delay_time = 0
        for candidate in self.candidates:
            candidate.delay_time = (candidate.last_seen_time -
                                    candidate.pcb.get_timestamp() + 1)
            if candidate.delay_time > max_delay_time:
                max_delay_time = candidate.delay_time
        for candidate in self.candidates:
            candidate.delay_time /= max_delay_time

    def _update_all_fidelity(self):
        """Update the fidelity of all path candidates."""
        self._update_disjointness_db()
        self._update_all_disjointness()
        self._update_all_delay_time()
        for candidate in self.candidates:
            candidate.update_fidelity(self.path_policy)

    def get_best_segments(self, k=None, sending=True):
        """
        Return the k best paths from the temporary buffer.

        Select the k best paths from the set of candidate paths. At the time of
        selection, the PathStore computes the fidelity of all candidate path
        segments and returns the k paths with the highest fidelity.

        When computing the fidelity, only the path properties that vary in time
        need to be recomputed: the freshness, delay, and disjointness. The
        length and number of peering links is constant.

        :param int k: default best set size.
        """
        if k is None:
            k = self.path_policy.best_set_size
        self._remove_expired_segments()
        self._update_all_fidelity()
        best_candidates = heapq.nlargest(k, self.candidates,
                                         lambda y: y.fidelity)  # CHANGE: Turned kw arg into regular arg.
        if sending:
            for candidate in best_candidates:
                candidate.sending()
        return [x.pcb for x in best_candidates]

    def get_latest_history_snapshot(self, k=None):
        """
        Return the latest k best paths from the history.

        :param int k: default best set size.
        """
        if k is None:
            k = self.path_policy.best_set_size
        best_paths = []
        if self.best_paths_history:
            for candidate in self.best_paths_history[0][:k]:
                best_paths.append(candidate.pcb)
        return best_paths

    def _remove_expired_segments(self):
        """Remove candidates if their expiration_time is up."""
        rec_ids = []
        now = SCIONTime.get_time()
        for candidate in self.candidates:
            if candidate.expiration_time <= now:
                rec_ids.append(candidate.id)
        self.remove_segments(rec_ids)

    def remove_segments(self, rec_ids):
        """
        Remove segments in 'rec_ids' from the candidates.

        :param list rec_ids: list of record IDs to remove.
        """
        self.candidates[:] = [c for c in self.candidates if c.id not in rec_ids]
        if self.candidates:
            self._update_all_fidelity()
            self.candidates = sorted(self.candidates, key=lambda x: x.fidelity,
                                     reverse=True)

    def get_segment(self, rec_id):
        """
        Return the segment for the corresponding record ID or None.

        :param str rec_id: ID of the segment to return.
        """
        for record in self.candidates:
            if record.id == rec_id:
                return record.pcb
        return None

    def __str__(self):
        """
        Return a string with the path store data.
        """
        ret = ["PathStore:"]
        for candidate in self.candidates:
            ret.append("  %s" % candidate)
        return "\n".join(ret)

