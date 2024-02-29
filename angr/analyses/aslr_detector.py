from . import Analysis
import logging

l = logging.getLogger(name=__name__)


class ASLRDetector(Analysis):
    def __init__(self, trace):
        self._trace = trace
        self._aslr_slides = {}

        self._identify_aslr_slides()

    @property
    def aslr_slides(self):
        return self._aslr_slides

    def _filter_idx(self, angr_addr, idx):
        slide = self._trace[idx] - angr_addr
        block = self.project.factory.block(angr_addr)
        legal_next = block.vex.constant_jump_targets
        if legal_next:
            return any(a + slide == self._trace[idx + 1] for a in legal_next)
        else:
            # the intuition is that if the first block of an initializer does an indirect jump,
            # it's probably a call out to another binary (notably __libc_start_main)
            # this is an awful fucking heuristic but it's as good as we've got
            return abs(self._trace[idx] - self._trace[idx + 1]) > 0x1000

    def _locate_entry_point(self, angr_addr):
        # ...via heuristics
        indices = set()
        threshold = 0x40000
        while not indices and threshold > 0x2000:
            for idx, addr in enumerate(self._trace):
                if ((addr - angr_addr) & 0xFFF) == 0 and (idx == 0 or abs(self._trace[idx - 1] - addr) > threshold):
                    indices.add(idx)

            indices = {i for i in indices if self._filter_idx(angr_addr, i)}
            threshold //= 2

        return indices

    def _identify_aslr_slides(self):
        """
        libraries can be mapped differently in the original run(in the trace) and in angr
        this function identifies the difference(called aslr slides) of each library to help angr translate
        original address and address in angr back and forth
        """
        # if we don't know whether there is any slide, we need to identify the slides via heuristics
        for obj in self.project.loader.all_objects:
            # do not analyze pseudo-objects
            if obj.binary_basename.startswith("cle##"):
                continue

            # heuristic 1: non-PIC  objects are loaded without aslr slides
            if not obj.pic:
                self._aslr_slides[obj] = 0
                continue

            # heuristic 2: library objects with custom_base_addr are loaded at the correct locations
            if obj._custom_base_addr:
                l.info("%s is assumed to be loaded at the address matching the one in the trace", obj)
                self._aslr_slides[obj] = 0
                continue

            # heuristic 3: entry point of an object should appear in the trace
            possibilities = None
            for entry in obj.initializers + ([obj.entry] if obj.is_main_bin else []):
                indices = self._locate_entry_point(entry)
                slides = {self._trace[idx] - entry for idx in indices}
                if possibilities is None:
                    possibilities = slides
                else:
                    possibilities.intersection_update(slides)

            if possibilities is None:
                continue

            if len(possibilities) == 0:
                raise Exception(
                    "Trace does not seem to contain object initializers for %s. "
                    "Do you want to have a Tracer(aslr=False)?" % obj
                )
            if len(possibilities) == 1:
                self._aslr_slides[obj] = next(iter(possibilities))
            else:
                raise Exception(
                    "Trace seems ambiguous with respect to what the ASLR slides are for %s. "
                    "This is surmountable, please open an issue." % obj
                )

    def translate_state_addr(self, state_addr, obj=None):
        if obj is None:
            obj = self.project.loader.find_object_containing(state_addr)
        if obj not in self._aslr_slides:
            raise Exception("Internal error: cannot translate address")
        return state_addr + self._aslr_slides[obj]

    def translate_trace_addr(self, trace_addr, obj=None):
        if obj is None:
            for obj, slide in self._aslr_slides.items():  # pylint: disable=redefined-argument-from-local
                if obj.contains_addr(trace_addr - slide):
                    break
            else:
                raise Exception("Can't figure out which object this address belongs to")
        if obj not in self._aslr_slides:
            raise Exception("Internal error: object is untranslated")
        return trace_addr - self._aslr_slides[obj]

    def compare_addr(self, trace_addr, state_addr):
        current_bin = self.project.loader.find_object_containing(state_addr)
        if current_bin is self.project.loader._extern_object or current_bin is self.project.loader._kernel_object:
            return False
        elif current_bin in self._aslr_slides:
            current_slide = self._aslr_slides[current_bin]
            return trace_addr == state_addr + current_slide
        elif ((trace_addr - state_addr) & 0xFFF) == 0:
            self._aslr_slides[current_bin] = trace_addr - state_addr
            return True
        # error handling
        elif current_bin:
            raise Exception(
                "Trace desynced on jumping into %s. "
                "Did you load the right version of this library?" % current_bin.provides
            )
        else:
            raise Exception("Trace desynced on jumping into %#x, where no library is mapped!" % state_addr)

