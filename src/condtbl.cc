#include <vector>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <time.h>

#include <Windows.h>

/// @summary Define the possible values that can appear in a condition table.
enum rule_e
{
    CONDITION_FALSE                    = 0, // the value must be false
    CONDITION_TRUE                     = 1, // the value must be true
    CONDITION_NULL                     = 2  // don't care what the value is
};

/// @summary Define some meaningful identitifiers for bit indices.
enum bit_ids_e
{
    PROOF_OF_ADDRESS                   = 0, // provided proof of address?
    PROOF_OF_IDENTITY                  = 1, // provided proof of identity?
    LOAN_LT_SALARY                     = 2, // loan amount <  annual salary?
    LOAN_GE_SALARY                     = 3, // loan amount >= annual salary?
    EXISTING_OWNER                     = 4, // owns another home?
    MAX_BITS                           = 32 // the maximum number of bits in a bitfield
};

/// @summary Bitflags indicating how a piece of information was verified.
enum verification_method_e
{
    VERIFICATION_METHOD_NONE           =  0,
    VERIFICATION_METHOD_STATE_ID       = (1 << 0),
    VERIFICATION_METHOD_PASSPORT       = (1 << 1),
    VERIFICATION_METHOD_UTILITY        = (1 << 2),
    VERIFICATION_METHOD_COUNT          =  4,
    VERIFICATION_METHOD_FORCE_32BIT    = 0xFFFFFFFFU
};

/// @summary Represent unique identifiers as 32-bit unsigned integers.
typedef uint32_t id_t;

/// @summary Global state we use for generating unique IDs.
static id_t Next_ID = 0;

/// @summary Stores a record in the traditional 'array of structures' form.
/// Instances of record_t are stored in a std::vector.
struct record_t
{
    id_t         id;
    char const  *address;
    char const  *identity;
    bool         owns_other_home;
    uint32_t     annual_salary;
    uint32_t     loan_amount;
    uint32_t     verify_address;
    uint32_t     verify_identity;
    // more fields (we aren't concerned with here)
    // ...
};

/// @summary Represents a growable list of IDs.
struct table_t
{
    size_t       count;
    size_t       capacity;
    id_t        *storage;
};

/// @summary Stores a collection of bits generated from a single column of the
/// condition table. These values are generated as a preprocessing step.
struct query_mask_t
{
    uint32_t     bits_false;  /// bit set if condition table entry is CONDITION_FALSE; xor'd
    uint32_t     bits_ignore; /// bit set if condition table entry is CONDITION_NULL; or'd
};

/**
Our condition table is defined as follows:

conditions:    | rules:
---------------+---------+---------+--------+--------+-------
Address Proof  | isFalse | null    | isTrue | isTrue | isTrue
Identity Proof | null    | isFalse | isTrue | isTrue | isTrue
Loan < Salary  | null    | null    | isTrue | null   | null
Loan >= Salary | null    | null    | null   | null   | isTrue
Home owner?    | null    | null    | null   | isTrue | null
---------------+---------+---------+--------+--------+--------
actions:       |         |         |        |        |
---------------+---------+---------+--------+--------+--------
immediate      |         |         | YES    | YES    |
manual         |         |         |        |        | YES
reject         | YES     | YES     |        |        |

Note that we are transposing the data in the table below; each
row in the table below corresponds to a single column from the
table above.
*/
static const size_t Table_Rows  = 5;
static const size_t Table_Cols  = 5;
static query_mask_t Table_Mask[Table_Cols];
static const rule_e Condition_Table[Table_Cols][Table_Rows] =
{
    { CONDITION_FALSE, CONDITION_NULL , CONDITION_NULL, CONDITION_NULL, CONDITION_NULL }, /* => REJECT    */
    { CONDITION_NULL , CONDITION_FALSE, CONDITION_NULL, CONDITION_NULL, CONDITION_NULL }, /* => REJECT    */
    { CONDITION_TRUE , CONDITION_TRUE , CONDITION_TRUE, CONDITION_NULL, CONDITION_NULL }, /* => IMMEDIATE */
    { CONDITION_TRUE , CONDITION_TRUE , CONDITION_NULL, CONDITION_NULL, CONDITION_TRUE }, /* => IMMEDIATE */
    { CONDITION_TRUE , CONDITION_TRUE , CONDITION_NULL, CONDITION_TRUE, CONDITION_NULL }  /* => MANUAL    */
};

/// @summary A list of sample addresses. NULL is considered to be invalid.
static const size_t  Address_Count = 10;
static char const   *Address_List[Address_Count] =
{
    "1234 Plumb Street",
    NULL,
    "5876 Clark Drive",
    "1192 Hollow Brook Way",
    "8592 Golden Apply Avenue",
    "97534 Dusty Chestnut Canyon",
    "3152 Crystal Brook Drive",
    NULL,
    "8476 Noble Fox Court",
    "6847 Lazy Panda Lane"
};

/// @summary A list of sample identities. NULL is considered invalid.
static const size_t  Identity_Count = 10;
static char const   *Identity_List[Identity_Count] =
{
    "Michael Behnke",
    "Chester Holloway",
    "Jennifer Jansen",
    "Robert Clarke",
    NULL,
    "Denise Masters",
    "Ann Kim-Lee",
    "James Smith",
    NULL,
    NULL
};

/// @summary An array if the possible verification method enum values.
/// We'll select values from this list randomly.
static const verification_method_e Verification_Methods[] =
{
    VERIFICATION_METHOD_NONE,
    VERIFICATION_METHOD_STATE_ID,
    VERIFICATION_METHOD_PASSPORT,
    VERIFICATION_METHOD_UTILITY
};

/// @summary A lookup table of strings for pretty-printing verification methods.
static char const *Verification_Method_Names[VERIFICATION_METHOD_COUNT] =
{
    "VERIFICATION_METHOD_NONE",
    "VERIFICATION_METHOD_STATE_ID",
    "VERIFICATION_METHOD_PASSPORT",
    "VERIFICATION_METHOD_UTILITY"
};

/// @summary Our record set, in traditional array-of-structures format.
static std::vector<record_t> Records;

/// @summary A table used to store all generated identifiers.
static table_t All_IDs;

/// Define our output tables. These correspond to the 'actions' in the condition table.
static table_t Output_Immediate;
static table_t Output_Manual;
static table_t Output_Reject;

/// @summary Generate a random value in the range [min, max] (inclusive).
/// @param min The inclusive lower-bound of the range.
/// @param max The inclusive upper-bound of the range.
/// @return A value in the range [min, max].
static inline uint32_t rand_range(uint32_t min, uint32_t max)
{
    // from http://c-faq.com/lib/randrange.html
    // we don't particularly care about quality randomness, so rand().
    return uint32_t(min + rand() / (RAND_MAX / (max - min + 1) + 1));
}

/// @summary Generates random verification flags.
/// @return A combination of verification_method_e.
static inline uint32_t gen_verifyflags(void)
{
    uint32_t flags  = VERIFICATION_METHOD_NONE;
    uint32_t count  = rand_range(0, VERIFICATION_METHOD_COUNT - 1);
    for (uint32_t i = 0; i < count; ++i)
    {
        uint32_t number = rand_range(0, VERIFICATION_METHOD_COUNT - 1);
        flags |= Verification_Methods[number];
    }
    return flags;
}

/// @summary Selects a random item from the Address_List.
/// @return A NULL-terminated string literal, or NULL.
static inline char const* gen_address(void)
{
    uint32_t number = rand_range(0, Address_Count - 1);
    return Address_List[number];
}

/// @summary Selects a random item from the Identity_List.
/// @return A NULL-terminated string literal, or NULL.
static inline char const* gen_identity(void)
{
    uint32_t number = rand_range(0, Identity_Count - 1);
    return Identity_List[number];
}

/// @summary Randomly chooses a boolean value.
/// @return Either true or false.
static inline bool gen_boolean(void)
{
    uint32_t number  = rand_range(0, 1);
    return  (number) ? true : false;
}

/// @summary Implements the business logic to determine whether an applicant's
/// supplied address has been verified and properly entered.
/// @param address A NULL-terminated string specifying the applicant's address.
/// @param flags The set of verification_method_e indicating how the data was verified.
/// @return true if the applicant has supplied verified proof of address.
static inline bool has_proof_of_address(char const *address, uint32_t flags)
{
    if ((address != NULL) && (flags != VERIFICATION_METHOD_NONE))
    {
        if (flags & VERIFICATION_METHOD_UTILITY)
        {
            // they must have also specified an additional form of proof.
            flags &= ~VERIFICATION_METHOD_UTILITY;
            return (flags != VERIFICATION_METHOD_NONE);
        }
        else return true;
    }
    else return false;
}

/// @summary Implements the business logic to determine whether an applicant's
/// supplied identity information has been verified and properly entered.
/// @param identity A NULL-terminated string specifying the applicant's identity.
/// @param flags The set of verification_method_e indicating how the data was verified.
/// @return true if the applicant has supplied verified proof of identity.
static inline bool has_proof_of_identity(char const *identity, uint32_t flags)
{
    if ((identity != NULL) && (flags != VERIFICATION_METHOD_NONE))
    {
        if (flags == VERIFICATION_METHOD_UTILITY)
        {
            // a utility bill is not a valid form of identity verification.
            return false;
        }
        else return true;
    }
    else return false;
}

/// @summary Determines whether the applicant's requested loan amount is less
/// than their annual salary.
/// @summary loan_amount The requested loan amount, in whole dollars.
/// @summary annual_salary The applicant's annual salary, in whole dollars.
/// @return true if the requested loan amount is less than the annual salary.
static inline bool loan_amount_less_than_salary(uint32_t loan_amount, uint32_t annual_salary)
{
    return (loan_amount < annual_salary);
}

/// @summary Determines whether the applicant's requested loan amount is greater
/// than or equal their annual salary.
/// @summary loan_amount The requested loan amount, in whole dollars.
/// @summary annual_salary The applicant's annual salary, in whole dollars.
/// @return true if the requested loan amount is greater than or equal to the annual salary.
static inline bool loan_amount_greater_or_equal_salary(uint32_t loan_amount, uint32_t annual_salary)
{
    return (loan_amount >= annual_salary);
}

/// @summary Determines whether an applicant is an existing homeowner.
/// @param owns_other_home true if the applicant owns another home.
/// @return The input value owns_other_home.
static inline bool existing_homeowner(bool owns_other_home)
{
    return owns_other_home;
}

/// @summary Sets a bit based on a boolean value.
/// @param condition The boolean value used to set or clear the specified bit.
/// @param bit_index The zero-based index of the bit to set if condition is true.
/// @return The value (1 << bit_index) if condition is true, or zero otherwise.
static inline uint32_t bit(bool condition, int bit_index)
{
    return condition ? (1U << bit_index) : 0;
}

/// @summary Generates a record with randomly selected data.
/// @param rec The record to populate.
static void make_record(record_t *rec)
{
    if (rec)
    {
        rec->id              = Next_ID++;
        rec->address         = gen_address();
        rec->identity        = gen_identity();
        rec->owns_other_home = gen_boolean();
        rec->annual_salary   = rand_range(10000U, 250000U);
        rec->loan_amount     = rand_range(1000U , 500000U);
        rec->verify_address  = gen_verifyflags();
        rec->verify_identity = gen_verifyflags();
    }
}

/// @summary Pretty-print verification method(s).
/// @param flags A combination of zero or more verification_method_e flags.
static void print_verifyflags(uint32_t flags)
{
    if (flags == VERIFICATION_METHOD_NONE)
    {
        printf("%s\n", Verification_Method_Names[0]);
        return;
    }
    for (size_t i = 1; i < VERIFICATION_METHOD_COUNT; ++i)
    {
        if (flags & Verification_Methods[i])
        {
            printf("%s", Verification_Method_Names[i]);
            flags &= ~Verification_Methods[i];
            if (flags != 0)
            {
                printf(", ");
            }
            else break;
        }
    }
    printf("\n");
}

/// @summary Print a record to stdout.
/// @param rec The record to print.
static void print_record(record_t const *rec)
{
    printf("ID:                    0x%08X\n", rec->id);
    printf("Address:               %s\n", rec->address);
    printf("Address Verification:  "); print_verifyflags(rec->verify_address);
    printf("Identity:              %s\n", rec->identity);
    printf("Identity Verification: "); print_verifyflags(rec->verify_identity);
    printf("Existing:              %d\n", (int) rec->owns_other_home);
    printf("Salary:                %u\n", rec->annual_salary);
    printf("Loan Amount:           %u\n", rec->loan_amount);
    printf("\n");
}

/// @summary Initializes an output table, allocating storage space for the
/// specified number of items.
/// @param table The table to initialize.
/// @param capacity The initial capacity.
static void table_init(table_t *table, uint32_t capacity=0)
{
    if (table)
    {
        table->count    = 0;
        table->capacity = capacity;
        table->storage  = NULL;
        if (capacity)
        {
            table->storage = (id_t*) malloc(capacity * sizeof(id_t));
        }
    }
}

/// @summary Frees the storage associated with an output table.
/// @param table The table to free.
static void table_free(table_t *table)
{
    if (table)
    {
        if (table->storage)
        {
            free(table->storage);
        }
        table->count    = 0;
        table->capacity = 0;
        table->storage  = NULL;
    }
}

/// @summary Resets a table to empty without freeing the associated storage.
/// @param table The table to clear.
static void table_clear(table_t *table)
{
    table->count = 0;
}

/// @summary Appends an ID to the table, growing if necessary.
/// @param table The table to update.
/// @param id The ID to append.
static void table_put(table_t *table, id_t id)
{
    if (table->count < table->capacity)
    {
        table->storage[table->count++] = id;
    }
    else
    {
        uint32_t m     = (uint32_t)(table->capacity * 2);
        table->storage = (id_t*) realloc(table->storage, m * sizeof(id_t));
        table->storage[table->count++] = id;
        table->capacity = m;
    }
}

/// @summary Speculatively appends an item to the table, growing if necessary.
/// @param table The table to update.
/// @param id The ID to append.
/// @param count The number of items to append, either 0 or 1.
static void table_put_speculative(table_t *table, id_t id, uint32_t count)
{
    if (table->count  < table->capacity)
    {
        table->storage[table->count] = id;
        table->count += count;
    }
    else if (count)
    {
        uint32_t m     =(uint32_t)(table->capacity * 2);
        table->storage = (id_t*) realloc(table->storage, m * sizeof(id_t));
        table->storage[table->count++] = id;
        table->capacity = m;
    }
}

/// @summary Generates bitfields using an array of structures data source.
/// @param dst The destination bitfields, of at least count elements.
/// @param src The array of source records, of at least count elements.
/// @param count The number of items to read from src and write to dst.
static void generate_bitfields(uint32_t *dst, record_t const *src, size_t count)
{
    for (size_t i = 0; i < count; ++i)
    {
        uint32_t bits  = 0;

        if (has_proof_of_address(src[i].address, src[i].verify_address))
        {
            bits |= 1U << PROOF_OF_ADDRESS;
        }
        if (has_proof_of_identity(src[i].identity, src[i].verify_identity))
        {
            bits |= 1U << PROOF_OF_IDENTITY;
        }
        if (loan_amount_less_than_salary(src[i].loan_amount, src[i].annual_salary))
        {
            bits |= 1U << LOAN_LT_SALARY;
        }
        if (loan_amount_greater_or_equal_salary(src[i].loan_amount, src[i].annual_salary))
        {
            bits |= 1U << LOAN_GE_SALARY;
        }
        if (existing_homeowner(src[i].owns_other_home))
        {
            bits |= 1U << EXISTING_OWNER;
        }

        dst[i] = bits;
    }
}

/// @summary Preprocesses a column of the condition table.
/// @param mask The output mask structure.
/// @param rules The input rules, representing a single column of the condition table.
/// @param row_count The number of rows in the condition table.
static void build_column_mask(query_mask_t *mask, rule_e const *rules, size_t row_count)
{
    uint32_t bits_false  = 0; // for false bits
    uint32_t bits_ignore = 0; // for don't care/unused bits
    for (size_t i = 0; i < row_count; ++i)
    {
        if (rules[i] == CONDITION_FALSE)
        {
            bits_false  |= (1U << i);
        }
        else if (rules[i] == CONDITION_NULL)
        {
            bits_ignore |= (1U << i);
        }
    }
    for (size_t i = row_count; i < 32; ++i)
    {
        // pad out unused bits so they don't affect the result.
        bits_ignore |= (1U << i);
    }
    mask->bits_false  = bits_false;
    mask->bits_ignore = bits_ignore;
}

/// @summary Classifies records based on a preprocessed condition table.
/// @param masks The masks generated from each column in the condition table.
/// @param outputs An array of output tables, one for each column.
/// @param column_count The number of columns in the condition table.
/// @param ids An array of IDs associated with each input record.
/// @param bits An array of bitfields computed for each input record.
/// @param record_count The number of input records.
static void classify(query_mask_t const *masks, table_t **outputs, size_t column_count, id_t const *ids, uint32_t const *bits, size_t record_count)
{
    for (size_t i = 0; i < record_count; ++i)
    {
        id_t     id        = ids[i];
        uint32_t bitfield  = bits[i];
        for (size_t j = 0; j < column_count; ++j)
        {
            table_t *output_table  =  outputs[j];
            uint32_t ignore_bits   =  masks[j].bits_ignore;               // bits indicating 'don't care' entries
            uint32_t xor_bits      =  masks[j].bits_false;                // bits indicating 'is false' entries
            uint32_t met_bits      = (bitfield ^ xor_bits) | ignore_bits; // all bits set if all conditions met
            uint32_t czero         = (met_bits + 1);                      // all bits clear if all conditions met
            uint32_t cmask         =~(czero  | -czero) >> 31;             // one if all conditions met, else zero
            output_table->storage[output_table->count]  = id;             // always write to the output table
            output_table->count   += (1 & cmask);                         // only increment count if the entry is valid
        }
    }
}

/// @summary Classifies a single input record based on the logic defined by the
/// condition table.
/// @param rec The record to classify.
static void check_record(record_t const *rec)
{
    bool proof_address   = has_proof_of_address(rec->address, rec->verify_address);
    bool proof_identity  = has_proof_of_identity(rec->identity, rec->verify_identity);
    bool loan_lt_salary  = loan_amount_less_than_salary(rec->loan_amount, rec->annual_salary);
    bool loan_ge_salary  = loan_amount_greater_or_equal_salary(rec->loan_amount, rec->annual_salary);
    bool owns_other_home = existing_homeowner(rec->owns_other_home);

    if (proof_address == false)
    {
        table_put(&Output_Reject, rec->id);
    }
    if (proof_identity == false)
    {
        table_put(&Output_Reject, rec->id);
    }
    if (proof_address && proof_identity && loan_lt_salary)
    {
        table_put(&Output_Immediate, rec->id);
    }
    if (proof_address && proof_identity && owns_other_home)
    {
        table_put(&Output_Immediate, rec->id);
    }
    if (proof_address && proof_identity && loan_ge_salary)
    {
        table_put(&Output_Manual, rec->id);
    }
}

/*/////////////////
//  Entry Point  //
/////////////////*/
#define UNUSED(x)         (void)sizeof(x)
#define NANOS_PER_USEC    1000ULL
#define NANOS_PER_MSEC    1000ULL * NANOS_PER_USEC
#define NANOS_PER_SECOND  1000ULL * NANOS_PER_MSEC

struct timer_t
{
    uint64_t start;       /// The starting time, in nanoseconds
    uint64_t end;         /// The ending time, in nanoseconds
};

static uint64_t
timestamp_in_ticks
(
    void
)
{
    LARGE_INTEGER ticks;
    QueryPerformanceCounter(&ticks);
    return (uint64_t) ticks.QuadPart;
}

static uint64_t
timestamp_counts_per_second
(
    void
)
{
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);
    return (uint64_t) frequency.QuadPart;
}

static uint64_t
timestamp_delta_nanoseconds
(
    uint64_t ts_enter, 
    uint64_t ts_leave
)
{
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);
    /* scale the tick value by the nanoseconds-per-second multiplier 
     * before scaling back down by ticks-per-second to avoid loss of precision.
     */
    return (1000000000ULL * (ts_leave - ts_enter)) / (uint64_t) frequency.QuadPart;
}

static inline void timer_start(timer_t *time)
{
    time->start = timestamp_in_ticks();
    time->end   = 0;
}

static inline void timer_stop(timer_t *time)
{
    time->end   = timestamp_in_ticks();
}

static inline uint64_t duration(timer_t const *time)
{
    return timestamp_delta_nanoseconds(time->start, time->end);
}

static inline float duration_sec(timer_t const *time)
{
    return float(timestamp_delta_nanoseconds(time->start, time->end)) / float(NANOS_PER_SECOND);
}

int main(int argc, char **argv)
{
    UNUSED(argc);
    UNUSED(argv);

    const size_t num_iterations = 10;

    srand((unsigned int) time(NULL));

    size_t record_count = 40000000;
    table_init(&Output_Immediate, (uint32_t) record_count);
    table_init(&Output_Manual   , (uint32_t) record_count);
    table_init(&Output_Reject   , (uint32_t) record_count);
    table_init(&All_IDs         , (uint32_t) record_count);

    // generate some records.
    printf("Generating test data of %u records...", (uint32_t) record_count);
    fflush(stdout);
    for (size_t i = 0; i < record_count; ++i)
    {
        record_t rec;
        make_record(&rec);
        Records.push_back(rec);
        table_put(&All_IDs, rec.id);
    }
    printf("DONE.\n");

    // perform one-time preprocessing.
    uint32_t *bitfields = (uint32_t*) malloc(record_count * sizeof(uint32_t));
    generate_bitfields(bitfields, &Records[0], Records.size());
    for (size_t i = 0; i < Table_Cols; ++i)
    {
        build_column_mask(&Table_Mask[i], Condition_Table[i], Table_Rows);
    }

    printf("Performing branchy processing...");
    fflush(stdout);
    timer_t branchy_time;
    timer_start(&branchy_time);
    for (size_t iter = 0; iter < num_iterations; ++iter)
    {
        table_clear(&Output_Reject);
        table_clear(&Output_Manual);
        table_clear(&Output_Immediate);
        for (size_t i = 0; i < record_count; ++i)
        {
            check_record(&Records[i]);
        }
    }
    timer_stop(&branchy_time);
    printf("DONE (%" PRIu64 " ns.)\n", duration(&branchy_time));
    printf("Reject:    %u.\n", (uint32_t) Output_Reject.count);
    printf("Manual:    %u.\n", (uint32_t) Output_Manual.count);
    printf("Immediate: %u.\n", (uint32_t) Output_Immediate.count);
    printf("\n");

    printf("Performing branchless processing...");
    fflush(stdout);
    timer_t branchless_time;
    table_t *outputs[] = {
        &Output_Reject,
        &Output_Reject,
        &Output_Immediate,
        &Output_Immediate,
        &Output_Manual
    };

    // filter the record set using SoA stream.
    timer_start(&branchless_time);
    for (size_t iter = 0; iter < num_iterations; ++iter)
    {
        table_clear(&Output_Reject);
        table_clear(&Output_Manual);
        table_clear(&Output_Immediate);
        classify(Table_Mask, outputs, Table_Cols, All_IDs.storage, bitfields, record_count);
    }
    timer_stop(&branchless_time);
    printf("DONE (%" PRIu64 " ns.)\n", duration(&branchless_time));
    printf("Reject:    %u.\n", (uint32_t) Output_Reject.count);
    printf("Manual:    %u.\n", (uint32_t) Output_Manual.count);
    printf("Immediate: %u.\n", (uint32_t) Output_Immediate.count);
    printf("\n");

    printf("Branchy processing took:    %f seconds.\n", duration_sec(&branchy_time));
    printf("Branchless processing took: %f seconds.\n", duration_sec(&branchless_time));

    free(bitfields);
    table_free(&All_IDs);
    table_free(&Output_Reject);
    table_free(&Output_Manual);
    table_free(&Output_Immediate);

    return 0;
}

